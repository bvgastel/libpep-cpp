// Author: Bernard van Gastel

#include "libpep.h"
#include <iostream>

int main(int argc, char** argv) {
  std::string subcommand;
  if (argc >= 2)
    subcommand = argv[1];
  try {
    if (subcommand == "generate-global-keys") {
      auto [pk, sk] = libpep::GenerateGlobalKeys();
      std::cerr << "Public global key: " << std::endl;
      std::cout << pk.hex() << std::endl;
      std::cerr << "Secret global key: " << std::endl;
      std::cout << sk.hex() << std::endl;
      return 0;
    }
    if (subcommand == "generate-pseudonym") {
      if (argc != 4) {
        std::cerr << "wrong number of arguments" << std::endl;
        return -1;
      }
      std::string identity = argv[2];
      auto pk = libpep::GlobalPublicKey::FromHex(argv[3]);
      auto local = libpep::GeneratePseudonym(identity, pk);
      std::cerr << local.hex() << std::endl;
      return 0;
    }
    if (subcommand == "convert-to-local-pseudonym") {
      if (argc != 6) {
        std::cerr << "wrong number of arguments" << std::endl;
        return -1;
      }
      auto p = libpep::GlobalEncryptedPseudonym::FromHex(argv[2]);
      std::string serverSecret = argv[3];
      std::string decryptionContext = argv[4];
      std::string pContext = argv[5];
      auto local = libpep::ConvertToLocalPseudonym(p, serverSecret, decryptionContext, pContext);
      local = libpep::RerandomizeLocal(local);
      std::cerr << local.hex() << std::endl;
      return 0;
    }
    if (subcommand == "make-local-decryption-key") {
      if (argc != 5) {
        std::cerr << "wrong number of arguments" << std::endl;
        return -1;
      }
      auto sk = libpep::GlobalSecretKey::FromHex(argv[2]);
      std::string serverSecret = argv[3];
      std::string decryptionContext = argv[4];
      auto localSk = libpep::MakeLocalDecryptionKey(sk, serverSecret, decryptionContext);
      std::cerr << localSk.hex() << std::endl;
      return 0;
    }
    if (subcommand == "decrypt-local-pseudonym") {
      if (argc != 4) {
        std::cerr << "wrong number of arguments" << std::endl;
        return -1;
      }
      auto local = libpep::LocalEncryptedPseudonym::FromHex(argv[2]);
      auto sk = libpep::LocalDecryptionKey::FromHex(argv[3]);
      auto p = libpep::DecryptLocalPseudonym(local, sk);
      std::cerr << p.hex() << std::endl;
      return 0;
    }
  } catch (std::exception& e) {
    std::cerr << "got exception: " << std::endl;
    std::cerr << e.what() << std::endl;
    return -1;
  }
  std::cerr << argv[0] << " expects at least one subcommand: " << std::endl;
  std::cerr << std::endl;
  std::cerr << argv[0] << " generate-global-keys" << std::endl;
  std::cerr << "  Outputs a public key and a secret key." << std::endl;
  std::cerr << std::endl;
  std::cerr << argv[0] << " generate-pseudonym [identity] [global-public-key]" << std::endl;
  std::cerr << "  Generates an encrypted global pseudonym." << std::endl;
  std::cerr << std::endl;
  std::cerr << argv[0] << " convert-to-local-pseudonym [pseudonym] [server-secret] [decryption-context] [pseudonymisation-context]" << std::endl;
  std::cerr << "  Converts a global encrypted pseudonym to a local encrypted pseudonym, decryptable by anybody that has the secret key as generated by make-local-decryption-key with the same decryption-context. The pseudonyms will be stable if the same pseudonymisation context is given. Server secret is a random string (so the pseudonymisation and decryption factors are not guessable)." << std::endl;
  std::cerr << std::endl;
  std::cerr << argv[0] << " make-local-decryption-key [global-secret-key] [server-secret] [decryption-context]" << std::endl;
  std::cerr << "  Creates a key that a party can use to decrypt an encrypted local pseudonym." << std::endl;
  std::cerr << std::endl;
  std::cerr << argv[0] << " decrypt-local-pseudonym [pseudonym] [local-decryption-key]" << std::endl;
  std::cerr << "  Decrypts the local encrypted pseudonym with a local decryption key as generated by make-local-decryption-key." << std::endl;
  std::cerr << std::endl;
  return -1;
}
