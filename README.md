# Generate TF files 
A script to generate terraform files from existing infrastructure using Terraformer. 

## Setup
- ensure AWS credentials is are added as environment variables.
- ensure jq package exists.

## Flow
- installs Terraformer if not exist
- run terraformer import
- add custom rules [L54](generate.sh#54) to trufflehog
- trufflehog scan
- redact potential secrets 
- trufflehog scan
- display result from trufflehog if any, or announce completion if no potential secrets detected
- cleanup

## customization
- to set regions for import [L4](generate.sh#L4)
- to set resources for import (use * for all) [L5](generate.sh#L5)
- to exclude resources from imported/generated [L6](generate.sh#L6)

## notes
- identitystore is added to exclusion because it failed the operation and may be an issue with Terraformer because an [issue](https://github.com/GoogleCloudPlatform/terraformer/issues/1832) is raised on their github.