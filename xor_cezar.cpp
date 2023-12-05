/*====================================
*	File name	  : encrypt_shell.cpp
*	Create Date	  : 16-11-2023
*	Last Modified : Mon 27 Nov 2023 02:53:50 PM CET
*	Comment		  :
*=====================================*/
// encrypt_shells.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <array>
#include <cstring>
#include <cstdint>
#include <memory>
#include <vector>

enum FOR :uint8_t {
	VBA = 0,
	CSHARP,
	C,
	PWRSH
};

const std::map<FOR, std::string> fmt{ {VBA,"%d"},{CSHARP,"0x%02x"}, {C,"\\x%02x",}, {PWRSH, "0x%02x"} };

inline uint8_t _xor(uint8_t orig, uint8_t* key, uint8_t keyl) {
	return ([&]()->uint8_t { for (int i = 0; i < keyl; i++) { orig ^= key[i]; } return orig; }()) & 0xFF;
}

inline uint8_t _ceasar(uint8_t orig, uint8_t shift) {
	return ((orig + shift) & 0xFF);
}

FOR _get(std::string key) {
	if (key == "vba")
		return FOR::VBA;
	else if (key == "c")
		return FOR::C;
	else if (key == "csharp")
		return FOR::CSHARP;
	else
		return FOR::C;
}

void printdec(uint32_t len, std::string key, uint8_t kl, uint8_t shift, FOR _for) {
	if (_for == C) {
		std::cout << "unsigned char kl = " << std::to_string(kl) << ";\n" << std::endl;
		std::cout << "int bufsz {" << std::to_string(len) <<  "};" << std::endl;
		std::cout << "uint8_t key[] {";
		for (int i = 0; i < kl; i++)
			std::cout << "'" << key[i] << "',";
		std::cout << "};" << std::endl;
		std::cout << "std::unique_ptr<uint8_t []> buf{std::make_unique<uint8_t[]>(" << std::to_string(len) << ")};";
		std::cout << std::endl;
		std::cout << "for (uint32_t i = 0; i < " << std::to_string(len) << ";i++) {";
		std::cout << std::endl;
		std::cout << "    buf[i] = _xor(_ceasar(ebuff[i], " << std::to_string(shift) << "), key, kl); }";
		std::cout << std::endl;
		std::cout << std::endl;

		std::cout << "------------------------------------------------------\n";
		std::cout << "inline uint8_t _xor(uint8_t orig, uint8_t *key, uint8_t keyl) {\n\
return ([&]()->uint8_t {\n for (int i = 0; i < keyl; i++) { orig ^= key[i]; } return orig; }()) & 0xFF;\n}";
		std::cout << std::endl;
		std::cout << std::endl;

		std::cout << "inline uint8_t _ceasar(uint8_t orig, uint8_t shift) {\n\
 return ((orig + shift) & 0xFF); }";
		std::cout << std::endl;
		std::cout << std::endl;

	}
	else if (_for == CSHARP){
		std::cout << "int size = ebuff.Length;\n";
		std::cout << "int [] k = new int[] {";
		for (int i = 0; i < kl; i++)
			std::cout << "'" << key[i] << "',";
		std::cout << "};\n";
		std::cout << "byte kl = " << std::to_string(kl) << ";\n\
		byte[] buf = new byte[" << std::to_string(len) << "];\n\
	for (uint i = 0; i < " << std::to_string(len) << "; i++)\n\
	{\n\
		\tbuf[i] = _xor(_ceasar(ebuff[i], " << std::to_string(shift) << "), k, kl);\n\
	}\n";

		std::cout << "------------------------------------------------------\n";
		std::cout << "private byte _xor(byte orig, int [] key, byte keyl) {\n\
		   for (int i = 0; i < keyl;i++) \n\
                      orig ^= (byte)key[i]; \n\
	        return (byte)(orig & 0xFF); \n\
    }";
		std::cout << std::endl;
		std::cout << std::endl;

		std::cout << "private byte _ceasar(byte orig, byte shift) {\n\
		return (byte)((orig + shift) & 0xFF); }";
		std::cout << std::endl;
		std::cout << std::endl;
	}
	else if (_for == VBA) {
		;
	}
	else {
		;
	}
	std::cout << std::endl;
	std::cout << std::endl;
}

void dump_shell(const std::vector<uint8_t> &buffer, uint32_t sz, FOR _for) {
	std::string encfmt = fmt.at(_for);
	std::cerr << "Using enc: " << encfmt << "(" << sz << "), _for: " << (int)_for <<  std::endl;
	if (_for == C)
		printf("uint8_t ebuff[]={\"");
	else if (_for == CSHARP) {
		printf("byte[] ebuff = new byte[%d] {",sz);
	}
	else if (_for == PWRSH) {
		printf("[Byte[]] $ebuff = ");
	}
	for (uint32_t i = 0; i < sz; i++) {
		printf(encfmt.c_str(), buffer[i]);
		if ((i + 1) == sz) {
			if (_for == C)
				printf("\"");
			if (_for == CSHARP || _for == C)
				printf("};");
			break;
		}
		if (_for != C)
			printf(",");
		if (_for == VBA) {
			if ((i == 49) || ((i > 50) && !((i+1) % 50))) {
				printf(" _");
				printf("\n");
			}
		}
		else {
			if ((i == 12) || ((i > 13) && !((i+1) % 13))) {
				if (_for == C) {
					printf("\"\n\"");
					continue;
				}
				printf("\n");
			}
		}
	}
	std::cout << std::endl;
	std::cout << std::endl;
}

void get_num(std::wifstream &f, std::vector<uint8_t> &numbers, bool isvba = false) {
	char num[4]{0};
	uint8_t cnum{0};
	uint8_t byte{0};
	uint8_t prev{0};
	bool grab{false}, init{false};
	auto isnum = [](char c)->bool { return ((c > 0x2f && c < 0x3a) ? true : ((c > 0x40 && c < 0x47) ? true : (c > 0x60 && c < 0x67) ? true : false)); };
	std::string x = "";
	while (!f.eof()) {
		byte = f.get();
		if (isvba) {
			if (!init) {
				switch (byte) {
					case 'A':
						x = byte;
						break;
					case 'r':
						if (prev == 'A')
							x += byte;
						else if (prev == 'r')
							x += byte;
						else
							x.clear();
						break;
					case 'a':
						if (prev == 'r')
							x += byte;
						else
							x.clear();
						break;
					case 'y':
						if (prev == 'a')
							x += byte;
						else
							x.clear();
						break;
					case '(':
						if (prev == 'y')
							x += byte;
						else
							x.clear();
						if (isvba) {
							std::cerr << "X: " << x << std::endl;
							if (x == "Array(")
								grab = init = true;
							x.clear();
						}
						break;
				}
				prev = byte;
				continue;
			}
		}
		switch(byte) {
			case '\\':				
				if (grab) {
					num[cnum] = 0;
					numbers.emplace_back((isvba)?(uint8_t)atoi(num):(uint8_t)strtol(num, nullptr, 16));
					cnum = 0;								
				}
				grab = !grab;
				break;
			case 'x':
				if (prev == '0' || prev == '\\')
					grab = true;
				break;
			case ',':
			case '"':
			case '}':
			case ')':
				if (grab) {
					num[cnum] = 0;
					numbers.emplace_back((isvba)?(uint8_t)atoi(num):(uint8_t)strtol(num, nullptr, 16));
				}
				grab = false;
				cnum = 0;								
				break;
			default:
				if (isnum(byte)) {
					if (!grab && isvba)
						grab = true;
				}
				if (grab) {
					num[cnum] = byte;
					cnum++;
				}
				break;
		}
		prev = byte;
	}
}

int main(int argc, char** argv)
{
	if (argc < 4) {
		std::cerr << "Missing something @1: file, @2: vba, csharp, c, @3: key, @4: cezar rot\n";
		return -1;
	}
	std::vector<uint8_t>	buffer;
	std::string mapk{argv[2]};
	int32_t rot{ 4 };
	std::string key = argv[3];
	uint8_t kl = key.length();//strlen(argv[3]);
	//memcpy(key.data(), argv[3], kl);
	rot = (argc == 5) ? std::atoi(argv[4]) : 4;
	FOR _for;
	try {
		_for = ((mapk == "csharp")?FOR::CSHARP:(mapk == "vba")?FOR::VBA:(mapk == "pwrsh")?PWRSH:FOR::C);
	}
	catch (std::out_of_range&) {
		std::cerr << "Bad arg @2: vba, csharp, c" << std::endl;
		return -1;
	}
	int32_t bsize{ 0 };
	std::wifstream	f{ argv[1] };
	if (f.is_open()) {
		std::vector<uint8_t> numbers;
		get_num(f, numbers, _for == VBA?true:false);
		std::cerr << "[i] Grabbed number, sz: " << numbers.size() << std::endl;
		for (auto c: numbers) {
			buffer.emplace_back(_ceasar(_xor(c, (uint8_t *)key.data(), kl), -(rot)));
		}
		bsize = buffer.size();
		std::cout <<"SZ: " << std::dec << buffer.size() << std::endl;
		dump_shell(buffer, buffer.size(), _for);
		printdec(bsize, key, kl, rot, _for);
	}
	else {
		std::cerr << "File open failed: " << strerror(errno) << "\n";
	}
}

