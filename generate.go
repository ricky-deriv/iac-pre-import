package main
import (
	"fmt"
	"os/exec"
	"os"
	"strings"
	"path/filepath"
	"bufio"
	"encoding/json"
)

// struct for trufflehog output 
type Report struct {
	SourceMetadata SourceMetadata `json:"SourceMetadata"`
	DetectorName string `json:"DetectorName"`
	Raw string `json:"Raw"`
	ExtraData ExtraData `json:"ExtraData"`
}

type ExtraData struct {
	Name string `json:"name"`
}

type SourceMetadata struct {
	Data Data `json:"Data"`
}

type Data struct {
	Filesystem Filesystem `json:"Filesystem"`
}

type Filesystem struct {
	File string `json:"file"`
	Line int `json:"line"`
}

// flow
func main() {
	// regions := [...]string{"us-east-1", "eu-west-1", "ap-southeast-1", "global"}
	regions := [...]string{"us-east-1"}
	resources := []string{"ec2_instance", "sqs"}
	excludes := []string{"identitystore"}

	cwd, _ := os.Getwd()

	fmt.Println("checking pre-reqs...")
	// check packages needed
	packages := [...]string{"terraform", "terraformer"}
	for _, pkg := range packages {
		cmd := exec.Command(pkg, "version")
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		if err != nil {
			fmt.Printf("Error: %s is not found. Ensure it is installed: %s\n", pkg, err)
			return
		} 
	}
	// check aws creds 
	awsCmd := exec.Command("aws", "sts", "get-caller-identity")
	awsCmd.Stderr = os.Stderr

	awsErr := awsCmd.Run()
	if awsErr != nil {
		fmt.Printf("Error: %s, no aws access: %s\n",  awsErr)
		return
	} 
	fmt.Println("pre-reqs fulfilled")

	// create directory
	generated_dir := "go-generated"
	err := os.Mkdir(generated_dir, 0755)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	// create terraform.tf file
	f, err := os.Create(generated_dir + "/terraform.tf")
	if err != nil {
		fmt.Println(err)
		return
	}
	_, writeErr := f.WriteString(`
terraform {
	required_providers {
		aws = {
			source  = "hashicorp/aws"
			version = "~> 5.31.0"
		}
	}
}`)

	if writeErr != nil {
		fmt.Println(writeErr)
				f.Close()
		return
	}
	f.Close()

	// terraform init the directory
	initCmd := exec.Command("terraform", "init")
	initCmd.Dir = generated_dir
	initCmd.Stderr = os.Stderr

	initErr := initCmd.Run()
	if initErr != nil {
		fmt.Printf("Error: %s fail to run: %s\n",  initErr)
		return
	} 

	// run terraformer import
	for _, region := range regions {
		importCmd := exec.Command("terraformer", "import", "aws",
			"--regions", region,
			"--resources", strings.Join(resources, ","),
			"--path-pattern", "{output}/{provider}/" + region + "/{service}",
			"--excludes", strings.Join(excludes, ","),
			"--profile", "")
		importCmd.Dir = generated_dir
		importCmd.Stderr = os.Stderr
		
		importErr := importCmd.Run()
		if importErr != nil {
			fmt.Printf("Error: %s fail to run: %s\n",  importErr)
			return
		} 
	}
	
	// find and remove 'empty' tf directories
	for _, region := range regions {
		region_dir := generated_dir + "/generated/aws/" + region 
		err := filepath.Walk(region_dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				err_name := fmt.Sprintf("%v", err)
				if !strings.Contains(err_name, "no such file or directory") {
					fmt.Printf("Error accessing path %s: %s\n", path, err)
				}
				return nil
			}
			if info.IsDir() {
				empty := true
				files, _ := os.ReadDir(path)
				for _, file := range files {
					if (file.Name() != "provider.tf" && file.Name() != "variables.tf" && !strings.HasSuffix(file.Name(), ".tfstate")) {
						empty = false
						break
					}
				}

				if empty {
					err := os.RemoveAll(path)
				if err != nil {
						fmt.Println(err)
				 }
				}
			}
			return nil
		})
		if err != nil {
			fmt.Printf("Error walking directory: %s\n", err)
		}
	}

	// create custom rule for trufflehog detection
	checkerF, checkErr := os.Create(generated_dir + "/config.yaml")
	if checkErr != nil {
		fmt.Println(checkErr)
		return
	}
	_, checkWriteErr := checkerF.WriteString(`detectors:
  - name: certificate authority
    keywords:
      - CERTIFICATE
    regex:
      adjective: -----BEGIN CERTIFICATE-----
  - name: AWS API key ID
    keywords:
      - AKIA
    regex:
      adjective: (?i)AKIA[0-9A-Z]{16}
  - name: userbase64
    keywords:
      - user_data
    regex:
      adjective: \buser_data.*
  - name: vpn-pre-shared-key
    keywords:
      - preshared_key
    regex:
      adjective: tunnel[12]_preshared_key`)

	if checkWriteErr != nil {
		fmt.Println(checkWriteErr)
			checkerF.Close()
		return
	}
	checkerF.Close()

	// create exclude for trufflehog
	checkerExF, checkExErr := os.Create(generated_dir + "/exclude.txt")
	if checkExErr != nil {
		fmt.Println(checkExErr)
		return
	}
	_, checkExWriteErr := checkerExF.WriteString(`
\*.tfstate
.terraform*`)

	if checkExWriteErr != nil {
		fmt.Println(checkExWriteErr)
			checkerExF.Close()
		return
	}
	checkerExF.Close()

	// run trufflehog [1st run]
	thCmd := exec.Command("docker", "run", "--rm", "-v", cwd + "/" + generated_dir + ":/path", "trufflesecurity/trufflehog:latest", "filesystem", "/path/generated", "--exclude-paths=/path/exclude.txt", "--config=/path/config.yaml", "--json")
	thCmd.Dir = generated_dir
	outputThFile, err := os.Create(generated_dir + "/output01.json")
	if err != nil {
			fmt.Println("Error creating output file:", err)
			return
	}
	thCmd.Stdout = outputThFile
	thCmd.Stderr = os.Stderr
	err = thCmd.Run()
	if err != nil {
		fmt.Println("Error running command:", err)
		return
	}

	// redact secrets identified
	/// read errors from json
	fmt.Println("redacting process...")
	thfile, therr := os.Open(generated_dir + "/output01.json")
	if therr != nil {
		fmt.Println("Error opening file:", therr)
		return
	}
	scanner := bufio.NewScanner(thfile)
	for scanner.Scan() {
		var data Report
		if err := json.Unmarshal(scanner.Bytes(), &data); err != nil {
			fmt.Println("Error parsing JSON:", err)
			continue
		}
		fileName := strings.TrimPrefix(data.SourceMetadata.Data.Filesystem.File, "/path/")
		detectorName := data.ExtraData.Name
		// redact entire line
		if (detectorName == "certificate authority" || detectorName == "vpn-pre-shared-key" || detectorName == "userbase64") {
			// dont rely on linenumber of trufflehog it's not linenumber of text format
			lineNumber := data.SourceMetadata.Data.Filesystem.Line
			fmt.Println("redact by line num", lineNumber)
			fmt.Println(fileName)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
	fmt.Println("end of redaction...")
}





// regions
// resources
// excludes

// check if packages are installed:
// - terraformer
// - terraform

// create terraform.tf file
// terraform init
// run terraformer import for every region

// remove empty tf directories