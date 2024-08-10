#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/secblock.h>

// Read a line from a file into a SecByteBlock
CryptoPP::SecByteBlock readLineToSecByteBlock(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Unable to open file for reading.\n";
        return CryptoPP::SecByteBlock();
    }

    // Read the line from the file
    std::string line;
    if (!std::getline(file, line)) {
        std::cerr << "Error: Unable to read line from file.\n";
        return CryptoPP::SecByteBlock();
    }

    // Create a SecByteBlock and copy the line data into it
    CryptoPP::SecByteBlock block(line.size());
    std::memcpy(block.data(), line.data(), line.size());

    return block;
}

int main() {
    std::string filename = "keys.bin"; // Change this to the filename

    // Example usage: Read a line from the file into a SecByteBlock
    CryptoPP::SecByteBlock block = readLineToSecByteBlock(filename);

    if (block.size() > 0) {
        // Use the read block
        std::cout << "Read block (" << block.size() << " bytes): ";
        for (size_t i = 0; i < block.size(); ++i) {
            std::cout << std::hex << static_cast<int>(block[i]);
        }
        std::cout << std::endl;
    }

    return 0;
}
