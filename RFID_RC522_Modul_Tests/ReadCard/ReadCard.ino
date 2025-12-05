#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN  9
#define SS_PIN   10

MFRC522 mfrc522(SS_PIN, RST_PIN);

void setup() {
  Serial.begin(115200);
  while (!Serial);
  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("Karte auflegen zum Auslesen...");
}

void loop() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  Serial.print("Karten UID: ");
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();

  // Standard-Schlüssel (Key A) setzen
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

  // Erkennen ob 1K oder 4K Karte über SAK
  byte sak = mfrc522.uid.sak;
  int totalSectors = ((sak & 0x38) == 0x08) ? 16 : 40;

  Serial.print("Kartentyp: ");
  Serial.println(totalSectors == 16 ? "MIFARE Classic 1K" : "MIFARE Classic 4K");

  for (int sector = 0; sector < totalSectors; sector++) {
    int blocksPerSector = (sector < 32) ? 4 : 16;
    byte firstBlock = sector * 4;

    // Authentifizieren
    byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A,
                                          firstBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.print("Auth Fehler im Sektor ");
      Serial.print(sector);
      Serial.print(": ");
      Serial.println(mfrc522.GetStatusCodeName(status));
      continue;
    }

    // Alle Datenblöcke im Sektor lesen (letzter Block ist Trailer, überspringen)
    int dataBlocks = blocksPerSector - 1;
    for (int blockIndex = 0; blockIndex < dataBlocks; blockIndex++) {
      byte blockAddr = firstBlock + blockIndex;
      byte buffer[18];
      byte size = sizeof(buffer);

      status = mfrc522.MIFARE_Read(blockAddr, buffer, &size);
      if (status == MFRC522::STATUS_OK) {
        Serial.print("Block ");
        if (blockAddr < 10) Serial.print("0");
        Serial.print(blockAddr);
        Serial.print(": ");

        // Hex-Ausgabe
        for (byte i = 0; i < 16; i++) {
          if (buffer[i] < 0x10) Serial.print("0");
          Serial.print(buffer[i], HEX);
          Serial.print(" ");
        }

        // ASCII Ausgabe
        Serial.print(" | ");
        for (byte i = 0; i < 16; i++) {
          char c = buffer[i];
          Serial.print((c >= 32 && c <= 126) ? c : '.');
        }
        Serial.println();
      } else {
        Serial.print("Fehler beim Lesen von Block ");
        Serial.print(blockAddr);
        Serial.print(": ");
        Serial.println(mfrc522.GetStatusCodeName(status));
      }
    }
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  Serial.println("Karte ausgelesen.\n");
  delay(3000);
}

void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    if (buffer[i] < 0x10) Serial.print("0");
    Serial.print(buffer[i], HEX);
    Serial.print(" ");
  }
}
