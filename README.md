# Noobaa-MCG-AWS-STS
Proof of Concept for non AWS OCP Cluster with Data Foundation MCG using buckets on AWS with STS

## Overview
Here we will describe the steps to create an OIDC, integrate the OIDC into Openshift authentication, create the IAM and role on AWS to enable MCG to consume buckets using STS services.

This Readme is based on [this guide](https://github.com/noobaa/noobaa-operator/blob/master/doc/dev_guide/create_aws_sts_setup_on_minikube.md) adapted to Openshift and assumes that OCP cluster does have Data Foundation deployed (the tests were done with IBM Fusion) and Noobaa is deployed on the default ```openshift-storage``` namespace.

## Build an OIDC Configuration

We assume that valid AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN are in place in the shell session and also the OCP cluster is authenticated with ```oc login```.

### Create OIDC bucket

Set your variables
```
BUCKET_NAME=<your_oidc_bucket_name>
AWS_REGION=<your_aws_region>
```
Create the bucket to ba used as OIDC
```
aws s3api create-bucket --bucket ${BUCKET_NAME} --region ${AWS_REGION} --create-bucket-configuration LocationConstraint=${AWS_REGION}
aws s3api put-public-access-block --bucket ${BUCKET_NAME} --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
aws s3api put-bucket-ownership-controls --bucket bucket-temp4553 \
  --ownership-controls 'Rules=[{ObjectOwnership="BucketOwnerPreferred"}]'
```
These 3 commands are equivalent to use the the steps on AWS Console UI: S3 → Buckets → Create Bucket → Fill the bucket name + region → ACLs enabled → uncheck Block all public access → Use the rest of the defaults. 

### Extract the Openshift Kube APIserver public key:
Command to extract the public key from the certificate:
```
oc get -n openshift-kube-apiserver cm -o json bound-sa-token-signing-certs | jq -r '.data["service-account-001.pub"]' > sa-signer.pub
```

### Create the keys.json
Using the extracted public key from the certificate to create the fields needed for the keys.json

- `<public_signing_key_id>` is generated from the public key with:
```
PUBLIC_SIGNING_KEY=$(openssl rsa -in sa-signer.pub -pubin --outform DER | openssl dgst -binary -sha256 | openssl base64 | tr '/+' '_-' | tr -d '=')
```

- `<public_signing_key_modulus>` is generated from the public key with:

```
PUBLIC_SIGNING_KEY_MODULUS=$(openssl rsa -pubin -in sa-signer.pub -modulus -noout | sed  -e 's/Modulus=//' | xxd -r -p | base64 -w0 | tr '/+' '_-' | tr -d '=')
```
The -w0 is needed on Linux, if not on Linux, the PUBLIC_SIGNING_KEY_MODULUS must be a single line

- `<public_signing_key_exponent>` is generated from the public key with:

```
PUBLIC_SIGNING_KEY_EXPONENT=$(printf "%016x" $(openssl rsa -pubin -in sa-signer.pub -noout -text | grep Exponent | awk '{ print $2 }') |  awk '{ sub(/(00)+/, "", $1); print $1 }' | xxd -r -p | base64  | tr '/+' '_-' | tr -d '=')
```

- Creating the keys.json

```
cat <<EOF >keys.json
{
    "keys": [
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "${PUBLIC_SIGNING_KEY_ID}",
            "alg": "RS256",
            "n": "${PUBLIC_SIGNING_KEY_MODULUS}",
            "e": "${PUBLIC_SIGNING_KEY_EXPONENT}"
        }
    ]
}
EOF
```

### Create the openid-configuration

Set the variables
```
BUCKET_NAME=<your_oidc_bucket_name>
OPENID_BUCKET_URL="https://${BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com"
```
Create the openid-configuration file
```
cat <<EOF >openid-configuration
{
	"issuer": "${OPENID_BUCKET_URL}",
	"jwks_uri": "${OPENID_BUCKET_URL}/keys.json",
    "response_types_supported": [
        "id_token"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "claims_supported": [
        "aud",
        "exp",
        "sub",
        "iat",
        "iss",
        "sub"
    ]
}
EOF
```

### Upload the files to the bucket

Considering that ```BUCKET_NAME``` is already set

```
aws s3api put-object --bucket ${BUCKET_NAME} --key keys.json --body ./keys.json
aws s3api put-object --bucket ${BUCKET_NAME} --key '.well-known/openid-configuration' --body ./openid-configuration

aws s3api put-object-acl --bucket ${BUCKET_NAME} --key keys.json --acl public-read
aws s3api put-object-acl --bucket ${BUCKET_NAME} --key '.well-known/openid-configuration' --acl public-read
```

### Create AWS role and policy

Set the variables
```
ROLE_NAME=<your_role_name>
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
OIDC_PROVIDER=$(echo ${OPENID_BUCKET_URL} | sed -e "s/^https:\/\///")
POLICY_ARN="arn:aws:iam::aws:policy/AmazonS3FullAccess"
```
Create the trust.json file
```
cat <<EOF >trust.json
{
 "Version": "2012-10-17",
 "Statement": [
   {
     "Effect": "Allow",
     "Principal": {
       "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
     },
     "Action": "sts:AssumeRoleWithWebIdentity",
     "Condition": {
       "StringEquals": {
        "${OIDC_PROVIDER}:sub": [
          "system:serviceaccount:openshift-storage:noobaa",
          "system:serviceaccount:openshift-storage:noobaa-endpoint",
          "system:serviceaccount:openshift-storage:noobaa-core"
          ]
       }
     }
   }
 ]
}
EOF
```
Create the AWS Role and Policy
```
aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document file://trust.json --description "Role for MCG x STS"
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "${POLICY_ARN}"
```

### Create the OIDC on AWS

Set the variables
```
FINGERPRINT=$(echo | openssl s_client -servername ${OIDC_PROVIDER} -showcerts -connect ${OIDC_PROVIDER}:443 2>/dev/null | openssl x509 -fingerprint -noout | sed s/://g | sed 's/.*=//')
```
Configure the OIDC
```
cat <<EOF > create-open-id-connect-provider.json
{
  "Url": "{OPENID_BUCKET_URL}",
  "ClientIDList": [
    "openshift"
  ],
  "ThumbprintList": [
    "${FINGERPRINT}"
  ]
}
EOF

aws iam create-open-id-connect-provider --cli-input-json file://create-open-id-connect-provider.json
```

## Configuring Openshift to use the new OIDC

The follwing command will update OCP authentication configuration to add the newly created OIDC

```
oc patch authentication.config.openshift.io cluster --type "json" -p="[{\"op\": \"replace\", \"path\":\"/spec/serviceAccountIssuer\", \"value\":\"${OPENID_BUCKET_URL}\"}]"
```

## Testing the STS

If everything is working as expected we can test using the service account token from noobaa-core

```
MY_TOKEN_CORE=$(kubectl exec $(kubectl get pods -n openshift-storage | grep core | awk '{ print $1}') -n openshift-storage -- cat /var/run/secrets/openshift/serviceaccount/token)

aws sts assume-role-with-web-identity --role-arn arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME} --role-session-name "test" --web-identity-token ${MY_TOKEN_CORE}
```

This command should return something like:
```json
{
    "Credentials": {
        "AccessKeyId": "REDACTED",
        "SecretAccessKey": "ALSO REDACTED",
        "SessionToken": "LONG REDACTED",
        "Expiration": "2025-03-24T23:47:03+00:00"
    },
    "SubjectFromWebIdentityToken": "system:serviceaccount:openshift-storage:noobaa-core",
    "AssumedRoleUser": {
        "AssumedRoleId": "AAAAAAAAAAAAAAAAARRM:test",
        "Arn": "arn:aws:sts::999999999999:assumed-role/<your-role>/test"
    },
    "Provider": "arn:aws:iam::999999999999:oidc-provider/<your-oidc-bucket>.s3.<aws-region>.amazonaws.com",
    "Audience": "openshift"
}
```

## Creating the noobaa backing store pointing to an S3 bucket using STS

Creating the target bucket

```
aws s3api create-bucket --bucket poc-mcg-bstore1 --region ${AWS_REGION} --create-bucket-configuration LocationConstraint=${AWS_REGION}^C
```

The noobaa client (or command) must be download and extracted into your PATH

```
noobaa backingstore create aws-sts-s3 backingstore-sts --target-bucket poc-mcg-bstore1 --aws-sts-arn arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}
INFO[0000] ✅ Exists: NooBaa "noobaa"
INFO[0000] ✅ Created: BackingStore "backingstore-sts"
INFO[0000]
INFO[0000] NOTE:
INFO[0000]   - This command has finished applying changes to the cluster.
INFO[0000]   - From now on, it only loops and reads the status, to monitor the operator work.
INFO[0000]   - You may Ctrl-C at any time to stop the loop and watch it manually.
INFO[0000]
INFO[0000] BackingStore Wait Ready:
INFO[0000] ⏳ BackingStore "backingstore-sts" Phase is "": waiting...
INFO[0003] ⏳ BackingStore "backingstore-sts" Phase is "": waiting...
INFO[0006] ✅ BackingStore "backingstore-sts" Phase is Ready
INFO[0006]
INFO[0006]
INFO[0006] ✅ Exists: BackingStore "backingstore-sts"
INFO[0006] ✅ BackingStore "backingstore-sts" Phase is Ready

# BackingStore spec:
awsS3:
  awsSTSRoleARN: arn:aws:iam::443370681991:role/oidc-poc-role
  secret: {}
  targetBucket: poc-mcg-bstore1
type: aws-s3
```


