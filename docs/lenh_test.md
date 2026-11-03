/* lệnh test Trivy: trivy fs --severity CRITICAL .
nếu ko chạy được thì chạy lệnh trên thì dùng cái này để ép 
 trivy fs --include-dev-deps --scanners vuln package-lock.json */

/* lệnh test SBOM : trivy image --format cyclonedx --output sbom.json my-web-app:buggy */
/* lệnh test bảo mật User (whoami): docker run --rm my-web-app:buggy whoami*/