#include <iostream>
#include <ctime>
#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <mutex>
#include <map>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MAX_THREADS 8

std::string rand_string(size_t size) {
	srand(time(0));
	std::string const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	std::string final_str;
	final_str.reserve(size);
	for (unsigned i = 0; i < size; ++i) {
		const int random = rand() % (possible.length());
		final_str.push_back(possible.at(random));
	}
	return final_str;
}

void print_hash(const unsigned char* sha256) {
	for (size_t i = 0; i < 32; ++i) {
		std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(sha256[i]);
	}
	std::cout << std::dec << std::endl;
}

int main() {

	OpenSSL_add_all_algorithms();

	constexpr unsigned difficulty = 8; // Number of zero before
	uint64_t calculated_hashes = 0; // Total number of hashes calculated in the program

	std::string in;
	std::cout << "Entrez un message : ";
	std::cin >> in;

	uint64_t nonce = 0; // Initial nonce is equal to zero
	bool found = false; // This is set by a thread if a correct a has been found
	unsigned char* found_hash = reinterpret_cast<unsigned char*>(malloc(32)); // The final hash
	uint64_t found_nonce = 0; // The final nonce
	
	std::mutex nonce_mutex;
	std::mutex found_mutex;
	std::mutex calculated_hashes_mutex;
		
	std::thread* threads[MAX_THREADS];
	for (size_t i = 0; i < MAX_THREADS; ++i) {
		threads[i] = new std::thread([&nonce_mutex, &nonce, &in, &calculated_hashes_mutex, &calculated_hashes, &found_mutex, &found, &difficulty, found_hash, &found_nonce]() {
			for (;;) {

				uint64_t thread_nonce = 0;
				int nonce_size = 0;

				// Lock nonce, local save it & increment it
				nonce_mutex.lock();
				nonce_size = snprintf(NULL, 0, "%d", nonce);
				char *nonce_str = reinterpret_cast<char*>(malloc(nonce_size + 1));
				sprintf(nonce_str, "%d", nonce);
				thread_nonce = nonce;
				nonce++;
				nonce_mutex.unlock();

				// Create the string to hash
				std::string data = in;
				data.reserve(nonce_size);
				data.insert(0, nonce_str, nonce_size);
				free(nonce_str);

				// Calculate the hash
				unsigned char sha[32] = { 0 };
				SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), sha);

				// Increment gloal hashes count
				calculated_hashes_mutex.lock();
				calculated_hashes++;
				calculated_hashes_mutex.unlock();

				// Check leading zeroes
				int ref = 0;
				memcpy(&ref, sha, difficulty / 2);

				if (ref == 0) {
					std::cout << "hash found" << std::endl;
					found_mutex.lock();
					found_nonce = thread_nonce;
					memcpy(found_hash, sha, 32);
					found = true;
					found_mutex.unlock();
					break;
				}

			}
		});
	}

	std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
	std::chrono::high_resolution_clock::time_point t_last_updated = std::chrono::high_resolution_clock::now();

	for (;;) {
		std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> last_show_interval = t2 - t_last_updated;
		if (last_show_interval.count() > 2000) {
			t_last_updated = std::chrono::high_resolution_clock::now();
			std::chrono::duration<double, std::milli> span = t2 - t1;
			float ratio = span.count() / 1000;
			calculated_hashes_mutex.lock();
			std::cout << std::fixed << (calculated_hashes / ratio) << " hash(es)/s" << std::endl;
			calculated_hashes_mutex.unlock();

			found_mutex.lock();
			if (found) {
				std::cout << std::to_string(found_nonce) << in << std::endl;
				print_hash(found_hash);
				for (size_t i = 0; i < MAX_THREADS; ++i) {
					threads[i]->join();
					delete threads[i];
				}
			}
			found_mutex.unlock();
		}

		using namespace std::chrono_literals;
		std::this_thread::sleep_for(1s);
	}

	EVP_cleanup();

	return 0;
}