# Push all 8 versions sequentially to GitHub
$ErrorActionPreference = "Stop"

Write-Host "Pushing v0.1..."
git push origin 37f08d1:refs/heads/main v0.1

Write-Host "Pushing v0.2..."
git push origin 4161fa4:refs/heads/main v0.2

Write-Host "Pushing v0.3..."
git push origin e5bbd0c:refs/heads/main v0.3

Write-Host "Pushing v0.4..."
git push origin 0cb59b8:refs/heads/main v0.4

Write-Host "Pushing v0.5..."
git push origin 2155ec1:refs/heads/main v0.5

Write-Host "Pushing v0.6..."
git push origin 70ab5c9:refs/heads/main v0.6

Write-Host "Pushing v0.5.1..."
git push origin 0adfc88:refs/heads/main v0.5.1

Write-Host "Pushing v0.5.2..."
git push origin 341f87f:refs/heads/main v0.5.2

Write-Host "Pushing branch references and remaining tags..."
git push -u origin main
git push origin master
git push origin --tags

Write-Host "Successfully pushed all 8 versions to GitHub!"
