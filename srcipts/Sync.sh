cd ~/android/pe
repo init -u https://github.com/PixelExperience/manifest -b twelve-plus
repo sync -c -j$(nproc --all) --force-sync --no-clone-bundle --no-tags