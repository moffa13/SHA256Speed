#include <iostream>
#include <ctime>
#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <openssl/evp.h>
#include <openssl/sha.h>

std::string rand_string(unsigned int size) {
	srand(time(0));
	std::string const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	std::string final_str;
	for (unsigned i = 0; i < size; ++i) {
		const int random = rand() % (possible.length());
		final_str += possible.at(random);
	}
	return final_str;
}

int main() {

	OpenSSL_add_all_algorithms();

	constexpr uint64_t difficulty = 1'590'896'927'258;
	uint64_t calculated_hashes = 0;
	std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
	std::chrono::high_resolution_clock::time_point t_last = std::chrono::high_resolution_clock::now();
	unsigned nonce = 0;
	std::string rnd_str = rand_string(15);

	for (;;) {

		

		std::string data = std::to_string(nonce) + rnd_str;		

		unsigned char sha[32] = { 0 };
		SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), sha);
		calculated_hashes++;

		if (false) {

		}
		else {
			nonce++;
		}



		std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> last_show_interval = t2 - t_last;
		if (last_show_interval.count() > 2000) {
			t_last = std::chrono::high_resolution_clock::now();
			std::chrono::duration<double, std::milli> span = t2 - t1;
			std::cout << span.count() << " " << calculated_hashes << std::endl;
			float ratio = span.count() / 1000;
			std::cout << (calculated_hashes / ratio) << " hash(es)/s" << std::endl;
		}

		
		//std::cout << std::hex << sha << std::endl;

		using namespace std::chrono_literals;
		//std::this_thread::sleep_for(1s);
		


	}

	EVP_cleanup();

	return 0;
}