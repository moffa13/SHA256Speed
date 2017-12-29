#include <iostream>
#include <ctime>
#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <mutex>
#include <map>
#define FMT_SHARED
#include "include\fmt\format.h"
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

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

uint64_t swap_uint64(uint64_t val)
{
	val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
	val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
	return (val << 32) | (val >> 32);
}

void print_hash(const unsigned char* sha256) {
	for (size_t i = 0; i < 32; ++i) {
		std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(sha256[i]);
	}
	std::cout << std::dec << std::endl;
}

int main() {

	OpenSSL_add_all_algorithms();

	unsigned difficulty = 8; // Number of zero before
	size_t threads_n = 1; // Concurrent threads
	uint64_t nonce = 0; // Initial nonce is equal to zero

	uint64_t calculated_hashes = 0; // Total number of hashes calculated in the program

	std::string in;
	std::cout << "Entrez un message : ";
	std::cin >> in;

#ifndef _DEBUG
	std::cout << "Nombre de threads : ";
	std::cin >> threads_n;

	std::cout << "Nonce : ";
	std::cin >> nonce;

	std::cout << "Difficulte : ";
	std::cin >> difficulty;
	std::cout << std::endl;
#endif

	
	bool found = false; // This is set by a thread if a correct a has been found
	unsigned char* found_hash = reinterpret_cast<unsigned char*>(malloc(32)); // The final hash
	uint64_t found_nonce = 0; // The final nonce
	
	std::mutex nonce_mutex;
	std::mutex found_mutex;
	std::mutex calculated_hashes_mutex;
		
	std::thread** threads = reinterpret_cast<std::thread**>(malloc(threads_n * sizeof(std::thread*)));
	for (size_t i = 0; i < threads_n; ++i) {
		threads[i] = new std::thread([&nonce_mutex, &nonce, &in, &calculated_hashes_mutex, &calculated_hashes, &found_mutex, &found, &difficulty, found_hash, &found_nonce]() {
			
			uint64_t thread_nonce = 0;
			int nonce_size = 0;
			char *nonce_str = reinterpret_cast<char*>(malloc(32 + in.size()));
			bool break_for = false;
			
			for (;;) {

				// Lock nonce, local save it & increment it
				nonce_mutex.lock();
				if (found) break_for = true;
				thread_nonce = nonce;
				nonce++;
				nonce_mutex.unlock();
				if (break_for) break;

				int size = sprintf(nonce_str, "%d%s", thread_nonce, in.c_str());
				
				// Calculate the hash
				unsigned char sha[32] = { 0 };
				SHA256(reinterpret_cast<const unsigned char*>(nonce_str), size, sha);

				// Increment gloal hashes count
				calculated_hashes_mutex.lock();
				calculated_hashes++;
				calculated_hashes_mutex.unlock();

				// Check leading zeroes
				bool matches = true;

				for (size_t cur_byte = 0; cur_byte < difficulty / 2; ++cur_byte) {
					if (sha[cur_byte] != 0) {
						matches = false;
						break;
					}
				}

				if (matches && difficulty % 2 != 0) { // Needs one more check
					size_t last_byte_check = static_cast<size_t>(difficulty / 2);
					if (sha[last_byte_check] > 0x0F || sha[last_byte_check] == 0) {
						matches = false;
					}
				}

				if (matches) {
					std::cout << "hash found" << std::endl;
					found_mutex.lock();
					found_nonce = thread_nonce;
					memcpy(found_hash, sha, 32);
					found = true;
					found_mutex.unlock();
					break;
				}

			}

			free(nonce_str);
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
			std::cout << std::fixed << static_cast<int>(calculated_hashes / ratio) << " hash(es)/s" << std::endl;
			calculated_hashes_mutex.unlock();

			nonce_mutex.lock();
			std::cout << std::fixed << "Nonce : " << nonce << std::endl;
			nonce_mutex.unlock();

			bool break_for = false;

			found_mutex.lock();
			if (found) {
				std::cout << std::to_string(found_nonce) << in << std::endl;
				print_hash(found_hash);
				for (size_t i = 0; i < threads_n; ++i) {
					free(threads[i]);
				}
				free(threads);
				break_for = true;
			}
			found_mutex.unlock();
			if (break_for) break;

		}

		using namespace std::chrono_literals;
		std::this_thread::sleep_for(1s);
	}

	system("pause");

	EVP_cleanup();

	return 0;
}