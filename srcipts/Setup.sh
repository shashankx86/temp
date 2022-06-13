export USE_CCACHE=1
export CCACHE_EXEC=/usr/bin/ccache
sudo apt install git
cd ~/
git clone https://github.com/akhilnarang/scripts
cd scripts
./setup/android_build_env.sh
mkdir -p ~/bin
mkdir -p ~/android/pe
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo
git config --global user.email "shashankspis20@gmail.com"
git config --global user.name "shashankx86"
