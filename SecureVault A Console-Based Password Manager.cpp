#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <limits>

/**
 * SecureVault: A Console-Based Password Manager
 * 
 * This application demonstrates various Data Structures and Algorithms concepts:
 * - std::map for O(log n) lookup by website key
 * - std::vector for maintaining insertion order
 * - String manipulation and encryption algorithms
 * - File I/O operations
 * - Modular programming design
 */

class SecureVault {
private:
    // Structure to hold credential information
    struct Credential {
        std::string website;
        std::string username;
        std::string encryptedPassword;
        
        Credential() = default;
        Credential(const std::string& w, const std::string& u, const std::string& p) 
            : website(w), username(u), encryptedPassword(p) {}
    };
    
    // Data structures for efficient storage and retrieval
    std::map<std::string, size_t> websiteIndex;  // Maps website to vector index for O(log n) lookup
    std::vector<Credential> credentials;         // Maintains insertion order
    
    static const std::string VAULT_FILE;
    static const int ENCRYPTION_KEY = 7;  // Caesar cipher shift value
    
public:
    SecureVault();
    ~SecureVault();
    
    // Core functionality methods
    void addCredential();
    void searchCredential();
    void deleteCredential();
    void displayAllCredentials();
    void saveToFile();
    void loadFromFile();
    void showMenu();
    void run();
    
private:
    // Utility methods
    std::string encryptPassword(const std::string& password);
    std::string decryptPassword(const std::string& encryptedPassword);
    void clearScreen();
    void pauseExecution();
    std::string toLowerCase(const std::string& str);
    bool confirmAction(const std::string& action);
    void displayCredential(const Credential& cred, bool showPassword = false);
};

// Static member initialization
const std::string SecureVault::VAULT_FILE = "vault.txt";

/**
 * Constructor: Initializes the vault and loads existing data
 */
SecureVault::SecureVault() {
    std::cout << "=== SecureVault Password Manager ===" << std::endl;
    std::cout << "Initializing vault..." << std::endl;
    loadFromFile();
    std::cout << "Loaded " << credentials.size() << " credentials." << std::endl;
    pauseExecution();
}

/**
 * Destructor: Saves data before exit
 */
SecureVault::~SecureVault() {
    saveToFile();
    std::cout << "\nVault saved. Goodbye!" << std::endl;
}

/**
 * Caesar Cipher encryption implementation
 * Time Complexity: O(n) where n is the length of the password
 * Space Complexity: O(n) for the result string
 */
std::string SecureVault::encryptPassword(const std::string& password) {
    std::string encrypted = password;
    
    // Apply Caesar cipher with XOR enhancement for better security
    for (size_t i = 0; i < encrypted.length(); ++i) {
        encrypted[i] = static_cast<char>((encrypted[i] + ENCRYPTION_KEY) ^ (i % 256));
    }
    
    return encrypted;
}

/**
 * Caesar Cipher decryption implementation
 * Time Complexity: O(n) where n is the length of the encrypted password
 * Space Complexity: O(n) for the result string
 */
std::string SecureVault::decryptPassword(const std::string& encryptedPassword) {
    std::string decrypted = encryptedPassword;
    
    // Reverse the encryption process
    for (size_t i = 0; i < decrypted.length(); ++i) {
        decrypted[i] = static_cast<char>((decrypted[i] ^ (i % 256)) - ENCRYPTION_KEY);
    }
    
    return decrypted;
}

/**
 * Utility function to convert string to lowercase for case-insensitive operations
 * Time Complexity: O(n) where n is the length of the string
 */
std::string SecureVault::toLowerCase(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower;
}

/**
 * Clear screen utility (cross-platform compatible)
 */
void SecureVault::clearScreen() {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}

/**
 * Pause execution utility
 */
void SecureVault::pauseExecution() {
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

/**
 * Confirmation utility for destructive operations
 */
bool SecureVault::confirmAction(const std::string& action) {
    std::string response;
    std::cout << "Are you sure you want to " << action << "? (y/N): ";
    std::getline(std::cin, response);
    return toLowerCase(response) == "y" || toLowerCase(response) == "yes";
}

/**
 * Display a single credential with formatting
 */
void SecureVault::displayCredential(const Credential& cred, bool showPassword) {
    std::cout << std::string(50, '-') << std::endl;
    std::cout << "Website:  " << cred.website << std::endl;
    std::cout << "Username: " << cred.username << std::endl;
    
    if (showPassword) {
        std::cout << "Password: " << decryptPassword(cred.encryptedPassword) << std::endl;
    } else {
        std::cout << "Password: " << std::string(cred.encryptedPassword.length(), '*') << std::endl;
    }
    std::cout << std::string(50, '-') << std::endl;
}

/**
 * Add a new credential to the vault
 * Time Complexity: O(log n) for map insertion, O(1) for vector insertion
 */
void SecureVault::addCredential() {
    clearScreen();
    std::cout << "=== Add New Credential ===" << std::endl;
    
    std::string website, username, password;
    
    // Input validation and data collection
    std::cout << "Enter website: ";
    std::getline(std::cin, website);
    
    if (website.empty()) {
        std::cout << "Error: Website cannot be empty!" << std::endl;
        pauseExecution();
        return;
    }
    
    // Check if website already exists
    std::string websiteLower = toLowerCase(website);
    if (websiteIndex.find(websiteLower) != websiteIndex.end()) {
        std::cout << "Warning: Credential for this website already exists!" << std::endl;
        if (!confirmAction("overwrite it")) {
            pauseExecution();
            return;
        }
    }
    
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    
    if (username.empty()) {
        std::cout << "Error: Username cannot be empty!" << std::endl;
        pauseExecution();
        return;
    }
    
    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    
    if (password.empty()) {
        std::cout << "Error: Password cannot be empty!" << std::endl;
        pauseExecution();
        return;
    }
    
    // Encrypt password and store credential
    std::string encryptedPass = encryptPassword(password);
    Credential newCred(website, username, encryptedPass);
    
    // Update data structures
    if (websiteIndex.find(websiteLower) != websiteIndex.end()) {
        // Overwrite existing credential
        size_t index = websiteIndex[websiteLower];
        credentials[index] = newCred;
    } else {
        // Add new credential
        credentials.push_back(newCred);
        websiteIndex[websiteLower] = credentials.size() - 1;
    }
    
    std::cout << "\nCredential added successfully!" << std::endl;
    pauseExecution();
}

/**
 * Search for credentials by website
 * Time Complexity: O(log n) for map lookup
 */
void SecureVault::searchCredential() {
    clearScreen();
    std::cout << "=== Search Credential ===" << std::endl;
    
    if (credentials.empty()) {
        std::cout << "No credentials stored in vault." << std::endl;
        pauseExecution();
        return;
    }
    
    std::string website;
    std::cout << "Enter website to search: ";
    std::getline(std::cin, website);
    
    if (website.empty()) {
        std::cout << "Error: Website cannot be empty!" << std::endl;
        pauseExecution();
        return;
    }
    
    // Case-insensitive search using map
    std::string websiteLower = toLowerCase(website);
    auto it = websiteIndex.find(websiteLower);
    
    if (it != websiteIndex.end()) {
        std::cout << "\nCredential found:" << std::endl;
        const Credential& cred = credentials[it->second];
        displayCredential(cred, false);
        
        // Option to reveal password
        if (confirmAction("reveal password")) {
            displayCredential(cred, true);
        }
    } else {
        std::cout << "No credential found for website: " << website << std::endl;
        
        // Suggest similar websites
        std::cout << "\nSuggested websites:" << std::endl;
        int suggestions = 0;
        for (const auto& cred : credentials) {
            if (toLowerCase(cred.website).find(websiteLower) != std::string::npos) {
                std::cout << "- " << cred.website << std::endl;
                suggestions++;
                if (suggestions >= 3) break;  // Limit suggestions
            }
        }
        
        if (suggestions == 0) {
            std::cout << "No similar websites found." << std::endl;
        }
    }
    
    pauseExecution();
}

/**
 * Delete a credential by website
 * Time Complexity: O(n) due to vector reorganization after deletion
 */
void SecureVault::deleteCredential() {
    clearScreen();
    std::cout << "=== Delete Credential ===" << std::endl;
    
    if (credentials.empty()) {
        std::cout << "No credentials stored in vault." << std::endl;
        pauseExecution();
        return;
    }
    
    std::string website;
    std::cout << "Enter website to delete: ";
    std::getline(std::cin, website);
    
    if (website.empty()) {
        std::cout << "Error: Website cannot be empty!" << std::endl;
        pauseExecution();
        return;
    }
    
    std::string websiteLower = toLowerCase(website);
    auto it = websiteIndex.find(websiteLower);
    
    if (it != websiteIndex.end()) {
        size_t indexToDelete = it->second;
        const Credential& cred = credentials[indexToDelete];
        
        std::cout << "\nCredential to delete:" << std::endl;
        displayCredential(cred, false);
        
        if (confirmAction("delete this credential")) {
            // Remove from vector
            credentials.erase(credentials.begin() + indexToDelete);
            
            // Rebuild the index map since vector indices have changed
            websiteIndex.clear();
            for (size_t i = 0; i < credentials.size(); ++i) {
                websiteIndex[toLowerCase(credentials[i].website)] = i;
            }
            
            std::cout << "Credential deleted successfully!" << std::endl;
        } else {
            std::cout << "Deletion cancelled." << std::endl;
        }
    } else {
        std::cout << "No credential found for website: " << website << std::endl;
    }
    
    pauseExecution();
}

/**
 * Display all stored credentials
 * Time Complexity: O(n) where n is the number of credentials
 */
void SecureVault::displayAllCredentials() {
    clearScreen();
    std::cout << "=== All Stored Credentials ===" << std::endl;
    
    if (credentials.empty()) {
        std::cout << "No credentials stored in vault." << std::endl;
        pauseExecution();
        return;
    }
    
    std::cout << "Total credentials: " << credentials.size() << std::endl << std::endl;
    
    // Display credentials in insertion order
    for (size_t i = 0; i < credentials.size(); ++i) {
        std::cout << "[" << (i + 1) << "] ";
        displayCredential(credentials[i], false);
        std::cout << std::endl;
    }
    
    pauseExecution();
}

/**
 * Save all credentials to file
 * Time Complexity: O(n) where n is the number of credentials
 */
void SecureVault::saveToFile() {
    std::ofstream file(VAULT_FILE);
    
    if (!file.is_open()) {
        std::cout << "Error: Could not open file for writing!" << std::endl;
        return;
    }
    
    // Write header with metadata
    file << "# SecureVault Data File" << std::endl;
    file << "# Format: website|username|encrypted_password" << std::endl;
    file << "# Total entries: " << credentials.size() << std::endl;
    file << std::endl;
    
    // Write credentials using pipe delimiter for better parsing
    for (const auto& cred : credentials) {
        file << cred.website << "|" << cred.username << "|" << cred.encryptedPassword << std::endl;
    }
    
    file.close();
}

/**
 * Load credentials from file
 * Time Complexity: O(n) where n is the number of credentials in file
 */
void SecureVault::loadFromFile() {
    std::ifstream file(VAULT_FILE);
    
    if (!file.is_open()) {
        // File doesn't exist, which is okay for first run
        return;
    }
    
    std::string line;
    credentials.clear();
    websiteIndex.clear();
    
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Parse line using pipe delimiter
        size_t pos1 = line.find('|');
        size_t pos2 = line.find('|', pos1 + 1);
        
        if (pos1 != std::string::npos && pos2 != std::string::npos) {
            std::string website = line.substr(0, pos1);
            std::string username = line.substr(pos1 + 1, pos2 - pos1 - 1);
            std::string encryptedPass = line.substr(pos2 + 1);
            
            // Validate data before adding
            if (!website.empty() && !username.empty() && !encryptedPass.empty()) {
                credentials.emplace_back(website, username, encryptedPass);
                websiteIndex[toLowerCase(website)] = credentials.size() - 1;
            }
        }
    }
    
    file.close();
}

/**
 * Display the main menu
 */
void SecureVault::showMenu() {
    clearScreen();
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "           SecureVault Password Manager" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "Current vault contains: " << credentials.size() << " credentials" << std::endl;
    std::cout << std::string(60, '-') << std::endl;
    std::cout << "1. Add New Credential" << std::endl;
    std::cout << "2. Search Credential" << std::endl;
    std::cout << "3. Delete Credential" << std::endl;
    std::cout << "4. View All Credentials" << std::endl;
    std::cout << "5. Save to File" << std::endl;
    std::cout << "6. Reload from File" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "Enter your choice: ";
}

/**
 * Main application loop
 */
void SecureVault::run() {
    int choice;
    
    do {
        showMenu();
        
        // Input validation for menu choice
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input! Please enter a number." << std::endl;
            pauseExecution();
            continue;
        }
        
        // Clear the input buffer
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        
        // Process menu choice
        switch (choice) {
            case 1:
                addCredential();
                break;
            case 2:
                searchCredential();
                break;
            case 3:
                deleteCredential();
                break;
            case 4:
                displayAllCredentials();
                break;
            case 5:
                saveToFile();
                std::cout << "Data saved to " << VAULT_FILE << std::endl;
                pauseExecution();
                break;
            case 6:
                loadFromFile();
                std::cout << "Data reloaded from " << VAULT_FILE << std::endl;
                std::cout << "Loaded " << credentials.size() << " credentials." << std::endl;
                pauseExecution();
                break;
            case 0:
                std::cout << "Exiting SecureVault..." << std::endl;
                break;
            default:
                std::cout << "Invalid choice! Please select a valid option (0-6)." << std::endl;
                pauseExecution();
                break;
        }
        
    } while (choice != 0);
}

/**
 * Main function - Entry point of the application
 */
int main() {
    try {
        SecureVault vault;
        vault.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}