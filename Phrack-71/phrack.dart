import 'dart:math';

class Caesar {
  int shift;
  Caesar({this.shift = 3});

  String encrypt(String message) {
    StringBuffer ciphertext = StringBuffer();
    for (int i = 0; i < message.length; i++) {
    	int charCode = message.codeUnitAt(i);
    	charCode = (charCode + shift) % 256;
    	ciphertext.writeCharCode(charCode);
	  }
	  return ciphertext.toString();
	}

  String decrypt(String ciphertext) {
    this.shift = -this.shift;
    String plaintext = this.encrypt(ciphertext);
    this.shift = -this.shift;
    return plaintext;
  }
}

void main() {
  print('Welcome to Caesar encryption');
  
  List<int> issues = [ 70, 71, 72 ];
  Random random = Random();
  final String message = 'Phrack Issue ${issues[random.nextInt(issues.length)]}';
  var caesar = Caesar();

  // Encrypt
  String ciphertext = caesar.encrypt(message);
  print(ciphertext);

  // Decrypt
  String plaintext = caesar.decrypt(ciphertext);
  print(plaintext);

}
