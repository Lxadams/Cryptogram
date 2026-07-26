cd code/server

cargo build
sudo setcap 'cap_net_bind_service=+ep' target/debug/server
./target/debug/server