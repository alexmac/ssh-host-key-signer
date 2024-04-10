# Use KMS to sign your SSH Host keys

- Private keys are stored in KMS, all signing stays in KMS
- A lambda is created that takes an EC2 instance identity doc as an input to generate a signed SSH host key. This could be replayed, but can't be faked so the lambda can't be used to sign other things or sign for IPs you don't want to support.
- You need to trigger this lambda periodically on the host depending on how long you want the keys to be valid for.


# Docs:

Step 1: update/run the terraform

Step 2: Test it on an EC2 Machine

```
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
IID=`curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document | base64 | tr -d '\n'`
IIDSIG=`curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/signature | tr -d '\n'`
HOST_KEY=`cat /etc/ssh/ssh_host_ed25519_key.pub`
PAY=`echo "{\"host_pub_key\":\"$HOST_KEY\",\"instance_identity_doc\":\"$IID\",\"instance_identity_doc_signature\":\"$IIDSIG\"}" | base64 | tr -d '\n'`
aws lambda invoke --function-name ssh-host-key-signer --payload $PAY response.json
cat response.json | jq -r .body.signed_host_key > /etc/ssh/ssh_host_ed25519_key.pub.certificate

echo "Add this to your known_hosts locally (modify * to match your ip/hostnames):"
cat response.json | jq -r .body.authorized_hosts_line
```

Configure your sshd to use the host cert:
```
echo "HostCertificate /etc/ssh/ssh_host_ed25519_key.pub.certificate" >> /etc/ssh/sshd_config
```

restart sshd, if it complains about the certificate with anything (even "no such file or directory") it means it was invalid in some way. Otherwise silence means it is working - "ssh -vvv user@ip" should show the server returning the certificate
