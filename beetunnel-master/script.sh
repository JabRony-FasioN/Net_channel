cd beetunnel/server/
sudo make uninstall
sudo make distclean
cd ../..
rm -rf beetunnel
git clone git@github.com:BEPb/beetunnel.git
cd beetunnel
sudo chmod +x compile
./compile