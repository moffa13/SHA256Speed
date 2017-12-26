#include <iostream>
#include <ctime>
#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <mutex>
#include <map>
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

void print_hash(const unsigned char* sha256) {
	for (unsigned i = 0; i < 32; ++i) {
		std::cout << std::hex << static_cast<int>(sha256[i]);
	}
	std::cout << std::dec << std::endl;
}

int main() {

	OpenSSL_add_all_algorithms();

	constexpr unsigned difficulty = 3; // Number of zero before
	uint64_t calculated_hashes = 0;
	std::mutex calculated_hashes_mutex;

	for (;;) {
		std::string const rnd_str = rand_string(10);

		unsigned nonce = 0;
		bool found = false;
		unsigned char* found_hash = reinterpret_cast<unsigned char*>(malloc(32));
		std::mutex nonce_mutex;
		std::mutex found_mutex;
		
		std::thread* threads[4];
		for (size_t i = 0; i < 4; ++i) {
			threads[i] = new std::thread([&nonce_mutex, &nonce, &rnd_str, &calculated_hashes_mutex, &calculated_hashes, &found_mutex, &found, &difficulty, found_hash]() {
				for (;;) {

					found_mutex.lock();
					if (found) {
						break;
					}
					found_mutex.unlock();

					int nonce_size = 0;
					nonce_mutex.lock();
					nonce_size = snprintf(NULL, 0, "%d", nonce);
					char *nonce_str = reinterpret_cast<char*>(malloc(nonce_size + 1));
					sprintf(nonce_str, "%d", nonce);
					nonce++;
					nonce_mutex.unlock();
					std::string data = rnd_str;
					data.reserve(nonce_size);
					data.insert(0, nonce_str, nonce_size);
					free(nonce_str);

					unsigned char sha[32] = { 0 };
					SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), sha);
					calculated_hashes_mutex.lock();
					calculated_hashes++;
					calculated_hashes_mutex.unlock();

					int ref = 0;
					memcpy(&ref, sha, difficulty);

					if (ref == 0) {
						std::cout << "hash found" << std::endl;
						found_mutex.lock();
						memcpy(found_hash, sha, 32);
						found = true;
						found_mutex.unlock();
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
				if (found) {
					for (size_t i = 0; i < 4; ++i) {
						threads[i]->join();
						delete threads[i];
					}
					print_hash(found_hash);
				}
			}

			using namespace std::chrono_literals;
			std::this_thread::sleep_for(1s);
		}
		

		

	}

	

	EVP_cleanup();

	return 0;
}