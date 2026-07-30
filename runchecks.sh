cd code/server
echo "Linting server code..."
cargo clippy
echo "Formatting server code..."
cargo fmt

# cd ../client
# echo "Linting client code..."
# cargo clippy
# echo "Formatting client code..."
# cargo fmt

cd ../utils
echo "Linting utils code..."
cargo clippy
echo "Formatting utils code..."
cargo fmt