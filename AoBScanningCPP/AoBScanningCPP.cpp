#include <iostream>
#include <iomanip>
#include <vector>
#include <conio.h>
#include "memory.h" 

/*

        free to use, coded by zJuvee <3
        the commented lines are to replace the pattern found with another pattern
        uses: this can be used to scan strings or replace strings in a process memory
*/

int main()
{
    c_fn_memory memory; 

    /* difficult to manipulate process, LSA & PPA <- protection*/
    const char* processName = "lsass.exe"; 
    std::vector<std::string> patterns = {
        "6B 65 79 61 75 74 68 2E 77 69 6E 30 59 30", // keyauth.win0Y0
        "61 70 69 2D 77 6F 72 6B 65 72 2E 6B 65 79 61 75 74 68 2E 77 69 6E", // api-workker.keyauth.win
        "6B 65 79 61 75 74 68 2E 77 69 6E 30", // keyauth.win0
        "6B 65 79 61 75 74 68 2E 77 69 6E" // keyauth.win
    };

    /*
    std::vector<std::pair<std::string, std::string>> patterns = {
        {"6B 65 79 61 75 74 68 2E 77 69 6E 30 59 30", "BA AD F0 0D"}, // keyauth.win0Y0 -> reemplazo
        {"61 70 69 2D 77 6F 72 6B 65 72 2E 6B 65 79 61 75 74 68 2E 77 69 6E", "DE AD BE EF"}, // api-workker.keyauth.win -> reemplazo
        {"6B 65 79 61 75 74 68 2E 77 69 6E 30", "AA BB CC DD"}, // keyauth.win0 -> reemplazo
        {"6B 65 79 61 75 74 68 2E 77 69 6E", "11 22 33 44"} // keyauth.win -> reemplazo
    };
    */

    if (memory.attack_process(processName)) {
        std::cout << "[+] Process ID: " << memory.processId << std::endl;

        // loop to find the patterns using AoB scanning
        
        for (const auto& pattern : patterns) {

        // for (const auto& [findPattern, replacePattern] : patterns) {


            std::cout << "\n[+] Looking for the pattern <" << pattern << ">" << std::endl;
            // search the addresses
            std::vector<LPVOID> foundAddresses = memory.find_byte(pattern);
            if (!foundAddresses.empty()) {
                std::cout << "[+] Addresses found: " << foundAddresses.size() << std::endl;
				std::cout << "===============================================" << std::endl;
                // print founded adress
                for (const auto& address : foundAddresses) {
                    std::cout << "[*] Address: " << std::hex << std::uppercase << address << std::endl;
                }
                std::cout << "===============================================\n" << std::endl;
                
                
                /*
                std::vector<BYTE> replacePatternBytes = memory.hex_string_to_byte(replacePattern);
                BOOL replaceSuccess = memory.replace_byte(findPattern, replacePattern);

                if (replaceSuccess) {
                    std::cout << "[+] Pattern replaced successfully" << std::endl;
                }
                else {
                    std::cout << "[-] Error replacing the pattern" << std::endl;
                }
                */
            }
            else {
                std::cout << "[-] pattern not found in scan" << std::endl;
            }
        }
    }
    else {
        std::cout << "[-] could not connect to the process" << std::endl;
    }

    _getch();
    return 0;
}
