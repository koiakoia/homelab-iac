# Sentinel CI/CD Setup

[![pipeline status](http://${GITLAB_IP}/root/sentinel-iac/badges/main/pipeline.svg)](http://${GITLAB_IP}/root/sentinel-iac/-/commits/main)

To enable automated deployment, you must add the following secret to your GitHub Repository (Settings > Secrets and variables > Actions):

1. **SENTINEL_SSH_KEY**: Paste the contents of your private key here (id_sentinel.key).

Once added, every push to the master branch will automatically update your cluster!
