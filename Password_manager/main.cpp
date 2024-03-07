#include <iostream>
#include <optional>
#include <vector>
#include <algorithm>
#include <string>
#include <set>
#include <ctime>
#include <fstream>
#include <chrono>

/**
 *  struktura dla tworzenia elementow typu PasswordRecord
 *  z elementami name, password, website, category i login
 */

struct PasswordRecord {
    std::string name;
    std::string password;
    std::string category;
    std::optional<std::string> website;
    std::string login;

};

/**
 * Zmienne globalne
 */

int decodeKey;
std::string path;
std::vector<PasswordRecord> passwordDatabase;
std::set<std::string> categories;
std::set<std::string> logins;
std::set<std::string> names;
std::string timeOfDecode;
std::string timeOfEncode;

/**
 * @param encodePhrase
 *      fraza dla szyfratora
 * @param decodeKey
 *      klucz dla szyfratora
 * @return
 *      zwraca rezultat kodowania
 */

auto encoder(std::string encodePhrase , int const& decodeKey) -> std::string {
    std::string result;
    srand (time(0));

    for (char c : encodePhrase) {
        result += char(c + decodeKey);
        result += char(c + decodeKey);
    }
    return result;
}

/**
 * @param decodePhrase
 *      fraza dla deszyfratora
 * @param decodeKey
 *      klucz dla deszyfratora
 * @return
 *      zwraca rezultat dekodowania
 */

auto decoder(std::string decodePhrase , int const& decodeKey) -> std::string {
    std::string result;
    for (int i = 0; i < decodePhrase.size(); i += 2) {
        result += char(decodePhrase[i] - decodeKey);
    }
    return result;
}

/**
 * @return zwraca czas teraz
 */

auto time()-> std::string {
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);

    std::tm* timeInfo = std::localtime(&currentTime);

    char formattedTime[20];
    std::strftime(formattedTime, sizeof(formattedTime), "%Y.%m.%d   %H:%M", timeInfo);

    return std::string(formattedTime);
}

/**
 * metoda deszyfruje elementy z pliku i zapisuje ich do PasswordRecord
 */

auto setData()-> void{

    auto file = std::fstream(path);
    auto str = std::string();

    auto index = int(0);

    auto login = std::string();
    auto password = std::string();
    auto category = std::string();
    auto name = std::string();

    while(file >> str){
        if (str == "------------------")
            break;

        switch (index) {
            case 0:
                login = decoder(str , decodeKey);
                logins.insert(login);
                break;
            case 1:
                password = decoder(str , decodeKey);
                break;
            case 2:
                category = decoder(str , decodeKey);
                categories.insert(category);
                break;
            case 3:
                if (str != "&"){
                    name += " " + decoder(str , decodeKey);
                    index--;
                }
                else
                    index++;

                if (index == 4){
                    PasswordRecord dataTMP;
                    dataTMP.login = login;
                    dataTMP.password = password;
                    dataTMP.category = category;
                    dataTMP.name = name;

                    names.insert(name);

                    passwordDatabase.push_back(dataTMP);
                    index = -1;
                    login = std::string();
                    password = std::string("");
                    category = std::string("");
                    name = std::string("");
                }
                break;
        }
        index++;
    }
}

/**
 * metoda szyfruje elementy z PasswordRecord i zapisuje ich do pliku
 */

auto saveData(){
    std::ofstream file(path, std::ios::out | std::ios::trunc);

    for (const auto& tmpData : passwordDatabase) {
        auto encodeLog = encoder(tmpData.login, decodeKey);
        auto encodePass = encoder(tmpData.password, decodeKey);
        auto encodeCategor = encoder(tmpData.category, decodeKey);
        auto encodeName = encoder(tmpData.name, decodeKey);

        auto all = encodeLog + " " + encodePass + " " + encodeCategor + " " + encodeName + " &";

        file << all << '\n';
    }

    file << "------------------" << '\n';
    file << "czas zaszyfrowania: " << timeOfEncode << '\n';
    file << "czas odszyfrowania: " << timeOfDecode << '\n';

    file.close();
}

/**
 * metoda sgeneruje haslo
 *
 * @param length
 *          dlugosc hasla
 * @param includeLetters
 *          czy haslo zawiera litery
 * @param includeSpecialChars
 *          czy haslo zawiera znaki specjalne
 * @return
 *          zwraca haslo
 */

std::string generatePassword(int length, bool includeLetters, bool includeSpecialChars) {
    std::string password;
    std::string charset;

    if(includeLetters) {
        charset += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }

    if(includeSpecialChars) {
        charset += "!@#$%^&*(){}[]:;<>,.?/~_+-=|";
    }

    srand(time(0));
    for(int i = 0; i < length; i++) {
        password += charset[rand() % charset.size()];
    }

    return password;
}

/**
 * @return
 *          zwraca kategorie
 */

std::set<std::string> getCategories() {
    std::set<std::string> uniqueCategories;
    for (const auto& record : passwordDatabase) {
        uniqueCategories.insert(record.category);
    }
    return uniqueCategories;
}

/**
 * metoda wyswietla kategorie
 */

void displayCategories() {
    std::set<std::string> categories = getCategories();
    std::cout << "Dostepne kategorie: " << std::endl;
    for (const auto& category : categories) {
        std::cout << category << std::endl;
    }
}

/**
 * metoda sprawdza czy podana kategoria istnieje
 *
 * @param categoryOption
 *          nazwa kategotii, wprowadzona uzytkownikiem
 * @return
 *          zwraca prawdu czy falsz
 */

bool isValidCategory(const std::string& categoryOption) {
    for (const auto& category : getCategories()) {
        if (category == categoryOption) {
            return true;
        }
    }
    return false;
}

/**
 * pomocnicza metoda dla addPasswordInteractive
 */

void addPassword(const PasswordRecord& record) {
    passwordDatabase.push_back(record);
}

/**
 * metoda sprawdza czy podane haslo juz istnieje
 *
 * @param password
 *          podane uzytkownikiem haslo
 * @return
 *          zwraca prawdu czy falsz
 */

bool passwordExists(const std::string& password) {
    return std::any_of(passwordDatabase.begin(), passwordDatabase.end(),
                       [&](const PasswordRecord& record) { return record.password == password; });
}

/**
 * metoda dodaje haslo
 */

void addPasswordInteractive() {
    PasswordRecord newRecord;
    int passwordOption;
    int passwordLength;
    bool includeLetters;
    bool includeSpecialChars;
    std::string categoryOption;
    int confirm;

    std::cout << "Wprowadz login:\n";
    std::cin >> newRecord.login;

    std::cout << "1. Wprowadz haslo\n2. Wygeneruj automatycznie\n";
    std::cin >> passwordOption;

    if (passwordOption == 1) {
        do {
            std::cout << "Wprowadz haslo:\n";
            std::cin >> newRecord.password;
            if (passwordExists(newRecord.password)) {
                std::cout << "To haslo juz istnieje. Czy chcesz dodac takie haslo? (0 - nie, 1 - tak)\n";
                std::cin >> confirm;
            } else {
                confirm = 1;
            }
        } while (confirm != 1);
    }
    else if (passwordOption == 2) {
        do {
            std::cout << "Wprowadz ilosc znakow:\n";
            std::cin >> passwordLength;
            std::cout << "Czy ma zawierac litery (0 - nie, 1 - tak):\n";
            std::cin >> includeLetters;
            std::cout << "Czy ma zawierac znaki specjalne (0 - nie, 1 - tak):\n";
            std::cin >> includeSpecialChars;

            newRecord.password = generatePassword(passwordLength, includeLetters, includeSpecialChars);
        } while (passwordExists(newRecord.password));
    }

    displayCategories();
    std::cout << "Wybierz kategorie:\n";
    std::cin >> categoryOption;

    while (!isValidCategory(categoryOption)) {
        std::cout << "Takiej kategorii nie ma. Prosze sprobowac ponownie.\n";
        std::cin >> categoryOption;
    }

    newRecord.category = categoryOption;

    std::cout << "Napisz komentarz:\n";
    std::cin.ignore();
    std::getline(std::cin, newRecord.name);

    addPassword(newRecord);
    saveData();
}

/**
 * metoda usuwa haslo, jesli uzytkownik napisze prawidlowo obecne haslo
 *
 * @param login
 *          podany uzytkownikiem login
 */

void removePassword(const std::string& login) {
    std::string currentPassword;
    std::cout << "Podaj obecne haslo:\n";
    std::cin >> currentPassword;

    auto it = std::find_if(passwordDatabase.begin(), passwordDatabase.end(),
                           [&](const PasswordRecord& record) { return record.login == login; });
    if (it != passwordDatabase.end() && it->password == currentPassword) {
        passwordDatabase.erase(it);
        saveData();
        std::cout << "Haslo zostalo usuniete.\n";
    } else {
        std::cout << "Podano niepoprawne haslo.\n";
    }
    saveData();
}

/**
 * metoda zmienia haslo, jesli uzytkownik poda prawidlowe obecne haslo
 *
 * @param login
 *          podany uzytkownikiem login
 *
 * @param newPassword
 *          nowe haslo uzytkownika
 */

void editPassword(const std::string& login, const std::string& newPassword) {
    std::string currentPassword;
    std::cout << "Podaj obecne haslo:\n";
    std::cin >> currentPassword;

    auto it = std::find_if(passwordDatabase.begin(), passwordDatabase.end(),
                           [&](const PasswordRecord& record) { return record.login == login; });
    if (it != passwordDatabase.end() && it->password == currentPassword) {
        it->password = newPassword;
        saveData();
        std::cout << "Haslo zostalo zmienione.\n";
    } else {
        std::cout << "Podano niepoprawne haslo.\n";
    }
}

/**
 * metoda poszukuje haslo
 *
 * @param keyword
 *          podany uzytkownikiem login
 */

std::vector<PasswordRecord> searchPasswords(const std::string& keyword) {
    std::vector<PasswordRecord> matchedRecords;
    for (const auto& record : passwordDatabase) {
        if (record.login.find(keyword) != std::string::npos) {
            std::cout << "Login: " << record.login << "\n";
            std::cout << "Haslo: " << record.password << "\n";
            matchedRecords.push_back(record);
        }
    }
    return matchedRecords;
}

/**
 * metoda sortujaca hasla po 1)kategoriam
 *                           2)login-am
 *                           3)Komentarzam
 *                           4)kategoriam i login-am
 */

void sortPasswords() {
    std::cout << "Wybierz typ sortowania: \n" << "1. kategoria\n" << "2. login\n" << "3. komentarz\n"
              << "4. kategoria i login\n";
    auto result = int();
    std::cin >> result;

    switch (result) {
        case 1:
            std::sort(passwordDatabase.begin(), passwordDatabase.end(),
                      [](const PasswordRecord& a, const PasswordRecord& b) {
                          return a.category < b.category;
                      });

            for (auto category : categories)  {
                std::cout << category << ": \n";
                for(auto dataTmp : passwordDatabase){
                    if (dataTmp.category == category){
                        std::cout << "login: " << dataTmp.login << " ; kommentarz: " << dataTmp.name << '\n';
                    }
                }
            }
            break;
        case 2:
            for (auto login : logins)  {
                for(auto dataTmp : passwordDatabase){
                    if (dataTmp.login == login){
                        std::cout << "login: " << dataTmp.login << " ; kommentarz: " << dataTmp.name << '\n';
                    }
                }
            }
            break;
        case 3:
            for (auto name : names)  {
                for(auto dataTmp : passwordDatabase){
                    if (dataTmp.name == name){
                        std::cout << "login: " << dataTmp.login << " ; kommentarz: " << dataTmp.name << '\n';
                    }
                }
            }
            break;
        case 4:

            auto tmpVector = std::vector<PasswordRecord>{};

            for (auto login : logins)  {
                for(auto dataTmp : passwordDatabase){
                    if (dataTmp.login == login){
                        tmpVector.push_back(dataTmp);
                    }
                }
            }

            for (auto category : categories)  {
                std::cout << category << ": \n";
                for(auto dataTmp : tmpVector){
                    if (dataTmp.category == category){
                        std::cout << "login: " << dataTmp.login << " ; kommentarz: " << dataTmp.name << '\n';
                    }
                }
            }
            tmpVector.clear();
            break;
    }

}

/**
 * metoda dodaje kategorie
 *
 * @param categoryName
 *      nazwa nowej kategorii
 */

void addCategory(const std::string& categoryName) {
    PasswordRecord newCategory;
    newCategory.category = categoryName;

    addPassword(newCategory);
}

/**
 * metoda usuwa kategorie i sprawdza czy napewno chcesz ja usunac
 *
 * @param categoryName
 *      nazwa kategorii ktora bedzie usunieta
 */

void removeCategory(const std::string& categoryName) {
    int confirm;
    std::cout << "Czy na pewno chcesz usunac kategorie " << categoryName << "? (0 - nie, 1 - tak)\n";
    std::cin >> confirm;

    if (confirm == 1) {
        passwordDatabase.erase(
                std::remove_if(
                        passwordDatabase.begin(), passwordDatabase.end(),
                        [&](const PasswordRecord& record) { return record.category == categoryName; }
                ),
                passwordDatabase.end()
        );
    }
}

/**
 * metoda wypisywania menu
 */

void printMenu() {
    std::cout << "\n1. Dodaj haslo\n";
    std::cout << "2. Usun haslo\n";
    std::cout << "3. Edytuj haslo\n";
    std::cout << "4. Wyszukaj haslo\n";
    std::cout << "5. Posortuj hasla\n";
    std::cout << "6. Dodaj kategorie\n";
    std::cout << "7. Usun kategorie\n";
    std::cout << "8. Wyjdz\n";
}

/**
 * metoda wypisywania menu
 */

void mainMenu() {
    int choice;
    std::string login;
    std::string password;
    std::string category;

    do {
        printMenu();
        std::cout << "\nWybierz opcje:\n";
        std::cin >> choice;

        switch (choice) {
            case 1: {
                if (getCategories().empty()) {
                    std::cout << "Najpierw dodaj kategorie.\n";
                    break;
                }
                addPasswordInteractive();
                break;
            }
            case 2: {
                std::cout << "Podaj nazwe hasla do usuniecia:\n";
                std::cin >> login;
                removePassword(login);
                break;
            }
            case 3: {
                std::cout << "Podaj nazwe hasla do edycji i nowe haslo:\n";
                std::cin >> login >> password;
                editPassword(login, password);
                break;
            }
            case 4: {
                std::cout << "Podaj slowo kluczowe do wyszukiwania:\n";
                std::cin >> login;
                searchPasswords(login);
                break;
            }
            case 5: {
                sortPasswords();
                break;
            }
            case 6: {
                std::cout << "Podaj nazwe nowej kategorii:\n";
                std::cin >> category;
                addCategory(category);
                displayCategories();
                break;
            }
            case 7: {
                std::cout << "Podaj nazwe kategorii do usuniecia:\n";
                std::cin >> category;
                removeCategory(category);
                displayCategories();
                break;
            }
            case 8:
                std::cout << "Koniec pracy programu.\n";
                break;
            default:
                std::cout << "Nieznana opcja!\n";
                break;
        }
    } while (choice != 8);
}

auto main() -> int {
    std::cout << "Wpisz klucz do szyfrowania:\n";
    std::cin >> decodeKey;

    auto variant = int();
    auto pathOptional = std::string();
    auto path1 = std::string(".\\Data\\data1.txt");
    auto path2 = std::string(".\\Data\\data2.txt");
    auto path3 = std::string(".\\Data\\data3.txt");

    std::cout << "Wybierz katalog: " << '\n' << "1. data 1\n" << "2. data 2\n" << "3. data 3\n" << "4) wpisac samemu\n";
    std::cin >> variant;

    switch (variant) {
        case 1:
            path = path1;
            break;
        case 2:
            path = path2;
            break;
        case 3:
            path = path3;
            break;
        case 4:
            std::cout << "Wprowadz sciezke:\n";
            std::cin >> pathOptional;
            path=pathOptional;
            break;
    }

    timeOfDecode = time();
    setData();
    timeOfEncode = time();
    saveData();
    mainMenu();

}

