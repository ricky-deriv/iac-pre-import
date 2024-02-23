# Generate TF files 
A script to generate terraform files from existing infrastructure using Terraformer. 

## customization
- to set regions for import [L4](generate.sh#L4)
- to set resources for import (use * for all) [L5](generate.sh#L5)
- to exclude resources from imported/generated [L6](generate.sh#L6)

## notes
- identitystore is added to exclusion because it failed the operation and may be an issue with Terraformer because an [issue](https://github.com/GoogleCloudPlatform/terraformer/issues/1832) is raised on their github.