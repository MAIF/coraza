cd ./coreruleset
git fetch --all
git checkout $(git tag --sort=-creatordate | head -n 1)
cd ..
cp -R ./coreruleset/rules/** ./rules/crs/