#include <MFRC522.h>
#include <SPI.h>

// MFRC522 Pins
#define RST_PIN 9
#define SS_PIN 10

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance
MFRC522::MIFARE_Key key;

// TonUINO Cookie (identifier for valid TonUINO cards)
static const uint32_t cardCookie = 322417479;

// Data structure for TonUINO cards
struct nfcTagObject {
  uint32_t cookie;
  uint8_t version;
  uint8_t folder;
  uint8_t mode;
  uint8_t special;
  uint8_t special2;
};

void setup() {
  Serial.begin(115200);
  Serial.println(F("\n=== TonUINO Data Eraser Tool ==="));
  Serial.println(F("Erases ONLY TonUINO data (Block 4)"));
  Serial.println(F("No other blocks are touched"));
  Serial.println(F("===================================\n"));
  
  // Initialize SPI
  SPI.begin();
  
  // Initialize MFRC522
  mfrc522.PCD_Init();
  delay(4);
  Serial.print(F("MFRC522 Version: "));
  mfrc522.PCD_DumpVersionToSerial();
  
  // Default key for MIFARE Classic (FFFFFFFFFFFF)
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }
  
  Serial.println(F("\nPlace a TonUINO card on the reader..."));
  Serial.println(F("Press RESET to cancel\n"));
}

void loop() {
  // Wait for new card
  if (!mfrc522.PICC_IsNewCardPresent()) {
    delay(100);
    return;
  }
  
  // Read card
  if (!mfrc522.PICC_ReadCardSerial()) {
    return;
  }
  
  // Display card information
  Serial.println(F("\n=== Card Detected ==="));
  
  // Display UID
  Serial.print(F("Card UID: "));
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();
  
  // Check card type
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.print(F("PICC type: "));
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
  
  // Try to read current TonUINO data
  Serial.println(F("\n=== Reading current data... ==="));
  nfcTagObject currentCard;
  
  if (readTonUINOData(&currentCard)) {
    displayCardData(currentCard);
    
    // Safety confirmation
    Serial.println(F("\n╔══════════════════════════════════════════╗"));
    Serial.println(F("║   Erase TonUINO data?                   ║"));
    Serial.println(F("║   Only Block 4 will be modified         ║"));
    Serial.println(F("╠══════════════════════════════════════════╣"));
    Serial.println(F("║ 'y' + ENTER = Erase TonUINO data        ║"));
    Serial.println(F("║ Any other key = Cancel                  ║"));
    Serial.println(F("╚══════════════════════════════════════════╝"));
    
    // Wait for user input
    while (!Serial.available()) {
      delay(10);
    }
    
    String input = Serial.readStringUntil('\n');
    input.trim();
    
    if (input == "y" || input == "Y") {
      Serial.println(F("\n▶▶▶ Erasing TonUINO data..."));
      
      // Erase TonUINO data
      if (wipeTonUINODataOnly()) {
        Serial.println(F("\n✓✓✓ TonUINO data successfully erased!"));
        
        // Read and display erased data
        Serial.println(F("\n=== New card data ==="));
        nfcTagObject wipedCard;
        if (readTonUINOData(&wipedCard)) {
          displayCardData(wipedCard);
        }
      } else {
        Serial.println(F("\n✗✗✗ ERROR: Could not erase data!"));
        Serial.println(F("Check if card uses default key (FFFFFFFFFFFF)"));
      }
    } else {
      Serial.println(F("\n▶ Operation cancelled!"));
    }
  } else {
    Serial.println(F("✗ Could not read card data"));
    Serial.println(F("Card may not have TonUINO data or uses different key"));
  }
  
  // Reset card
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  
  Serial.println(F("\n══════════════════════════════════════════"));
  Serial.println(F("Waiting for next card...\n"));
  delay(1000);
}

// Reads TonUINO data from Block 4
bool readTonUINOData(nfcTagObject *nfcTag) {
  MFRC522::StatusCode status;
  byte buffer[18];
  byte size = sizeof(buffer);
  
  // Block 4 is in Sector 1
  byte blockAddr = 4;
  byte trailerBlock = 7; // Sector 1 trailer block
  
  // Try to authenticate with default key
  status = mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Authentication failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  
  // Read Block 4
  status = (MFRC522::StatusCode)mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Reading failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  
  // Display raw data
  Serial.print(F("Block 4 raw: "));
  for (byte i = 0; i < 16; i++) {
    Serial.print(buffer[i] < 0x10 ? "0" : "");
    Serial.print(buffer[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
  
  // Interpret data
  uint32_t tempCookie;
  tempCookie = (uint32_t)buffer[0] << 24;
  tempCookie += (uint32_t)buffer[1] << 16;
  tempCookie += (uint32_t)buffer[2] << 8;
  tempCookie += (uint32_t)buffer[3];
  
  nfcTag->cookie = tempCookie;
  nfcTag->version = buffer[4];
  nfcTag->folder = buffer[5];
  nfcTag->mode = buffer[6];
  nfcTag->special = buffer[7];
  nfcTag->special2 = buffer[8];
  
  return true;
}

// Displays TonUINO card data
void displayCardData(nfcTagObject card) {
  Serial.println(F("══════════════════════════════════════════"));
  
  Serial.print(F("Cookie:   0x"));
  Serial.print(card.cookie, HEX);
  if (card.cookie == cardCookie) {
    Serial.println(F(" ✓ TonUINO card"));
  } else if (card.cookie == 0x00000000) {
    Serial.println(F(" ✗ Empty"));
  } else if (card.cookie == 0xFFFFFFFF) {
    Serial.println(F(" ✗ Factory default"));
  } else {
    Serial.println(F(" ✗ Unknown"));
  }
  
  Serial.print(F("Folder:   "));
  Serial.println(card.folder);
  
  Serial.print(F("Mode:     "));
  Serial.println(card.mode);
  
  Serial.print(F("Special:  "));
  Serial.println(card.special);
  
  Serial.print(F("Special2: "));
  Serial.println(card.special2);
  
  Serial.println(F("══════════════════════════════════════════"));
}

// Erases ONLY TonUINO data (Block 4)
bool wipeTonUINODataOnly() {
  MFRC522::StatusCode status;
  
  // Empty TonUINO data
  byte emptyData[16] = {
    0x00, 0x00, 0x00, 0x00,  // Cookie = 0
    0x00,                    // Version = 0
    0x00,                    // Folder = 0
    0x00,                    // Mode = 0
    0x00,                    // Special = 0
    0x00,                    // Special2 = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  
  // Block 4 in Sector 1
  byte blockAddr = 4;
  byte trailerBlock = 7;
  
  Serial.print(F("Authenticating... "));
  
  // Authenticate
  status = mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  
  if (status != MFRC522::STATUS_OK) {
    Serial.println(F("FAILED"));
    Serial.print(F("Error: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  
  Serial.println(F("OK"));
  
  // Write empty data to Block 4
  Serial.print(F("Writing to Block 4... "));
  
  status = mfrc522.MIFARE_Write(blockAddr, emptyData, 16);
  
  if (status != MFRC522::STATUS_OK) {
    Serial.println(F("FAILED"));
    Serial.print(F("Error: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  
  Serial.println(F("OK"));
  return true;
}

// Helper function: Output byte array
void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}