# Some info about how to configure jenkisn

Store the secrets in Jenkins Credentials

Create four credentials (kind → Secret text unless noted):

```groovy
withCredentials([
  string(credentialsId: 'wg.server.endpoint', variable: 'WG_SERVER_ENDPOINT'),
  string(credentialsId: 'wg.server.pubkey',   variable: 'WG_SERVER_PUBLIC_KEY'),
  string(credentialsId: 'wg.psk',             variable: 'WG_PRESHARED_KEY'),
  string(credentialsId: 'wg.client.privkey',  variable: 'CLIENT_PRIVATE_KEY')
]) {
  sh '''
    set -euo pipefail
    export WG_SERVER_ENDPOINT WG_SERVER_PUBLIC_KEY WG_PRESHARED_KEY CLIENT_PRIVATE_KEY
    envsubst '${WG_SERVER_ENDPOINT} ${WG_SERVER_PUBLIC_KEY} ${WG_PRESHARED_KEY} ${CLIENT_PRIVATE_KEY}' \
      < user_data.tmpl.sh > user_data.sh
  '''
}
```

Example on how to use AWS credentials in jenkis:

```groovy
stages {
    stage('Init') {
        steps {
            // region example: il-central-1
            withAWS(credentials: 'aws-ci', region: 'il-central-1') {
            sh '''
                terraform -chdir=infra init -input=false
            '''
            }
        }
    }
    stage('Plan') {
        steps {
            withAWS(credentials: 'aws-ci', region: 'il-central-1') {
            sh '''
                terraform -chdir=infra plan -out=tfplan -input=false
            '''
            }
        }
    }
    stage('Apply') {
        steps {
            // Optionally assume a role with stronger perms only here:
            withAWS(
            credentials: 'aws-ci',
            region: 'il-central-1',
            duration: 1800 // seconds
            ) {
            input message: 'Apply the plan?'
            sh '''
                terraform -chdir=infra apply -input=false -auto-approve tfplan
            '''
            }
        }
    }
}
```

How to update dns record via CLI:

```bash
# Get the EIP from terraform output
IP=$(terraform output -raw bulkintel_proxy_eip)
curl -u "user:password" \
  "https://freedns.afraid.org/nic/update?hostname=bulkintel.home-lab.home.kg&myip=${IP}"
```

Update dns record in jenkins:

```groovy
stage('Update DNS') {
      steps {
        // Needed if your TF backend is on AWS (S3/DynamoDB)
        withAWS(credentials: 'aws-ci', region: 'il-central-1', duration: 900) {
          script {
            // Read the output from state after apply
            env.BULKINTEL_IP = sh(
              script: 'terraform -chdir=infra output -raw bulkintel_proxy_eip',
              returnStdout: true
            ).trim()
            if (!env.BULKINTEL_IP) {
              error 'bulkintel_proxy_eip output is empty'
            }
          }
        }

        // FreeDNS credentials from Jenkins
        withCredentials([usernamePassword(
          credentialsId: 'freedns-creds',
          usernameVariable: 'FREEDNS_USER',
          passwordVariable: 'FREEDNS_PASS'
        )]) {
          sh '''
            set -euo pipefail
            curl -sSf -u "${FREEDNS_USER}:${FREEDNS_PASS}" \
              "https://freedns.afraid.org/nic/update?hostname=bulkintel.home-lab.home.kg&myip=${BULKINTEL_IP}"
          '''
        }
      }
}
```
