import 'dart:io';


String createFlag() {
  print("Content\t\t | Index");
  print("---------------- | -------------------");

  final List<String> values = [ 'deli', 'ph0wn{', '{', 'pico', 'le', 'croco', 'GH23{', 'caviar', 'champagne', 'drink', 'chocolate', 'yacht', '_', '@', '++', '+', 'loves', 'spa', 'masdescrocodiles.fr', 'lobster', 'shrimp', 'ferrari', 'rolls', 'royce', 'lamborghini', 'Monaco', 'Bahamas', 'Prokofiev', 'Mozart', 'Bach', 'Dvorak', 'Saint Saens', 's', '!', 'ome', 'lurp', 'cello', 'james', 'bond', 'with', 'it', 'cious', 'cryptax', 'mini', 'camaro', 'blackalps', 'grehack', 'radare', 'hack', '.', ' ', '}', 'lu', 'fr', 'chartreuse', 'chamrousse' ];
  final List<int> indexes = [943, 944, 529, 945, 946, 947, 948, 949, 950,951, 952,953,555, 231, 954, 535,955,956,957,958,959,960,961,962,963,964,965,966,967,968,969,970,971,972,973,974,975,976,977,978,979,980,981,982,983,984,985,986,987,29,794,534, 988,989,990,991];

  for (int i = 0; i<values.length; i++) {
    stdout.write(values[i]);
    stdout.write('\t\t | ');
    print(indexes[i]);
  }

  // GH23{_slurp_it_s_delicious_with_some_lobster!}
  String flag = values[6] + values[12] + values[32] + values[35] + values[12] + values[40] + values[12] + values[32] + values[12] + values[0] + values[41] + values[12] + values[39] + values[12] + values[32] + values[34] + values[12] + values[19] + values[33] + values[51];
  //print('DEBUG: $flag');
  return flag;
}

void main() {
     print("====== DART.Y - Your Secure & Smart Fridge ======");
     stdout.write("Password: ");
     String? input = stdin.readLineSync();
     if (input == createFlag()) {
     	print("Door opens, get your caviar and flag!");
     } else {
        print("The door is locked");
     }
     print("=====================");
}
