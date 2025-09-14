hugo --cleanDestinationDir
git add -f public
git commit -m "Build site"
git subtree split --prefix public -b gh-pages-deploy
git push origin gh-pages-deploy:gh-pages --force
git branch -D gh-pages-deploy
git reset HEAD~1 --soft
git restore --staged public
