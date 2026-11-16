// SPDX-License-Identifier: Apache-2.0
// Aegis "legacy node": an Arduino Uno that behaves like an old sensor. It has no keys, no
// secure boot and no measurements, so it cannot attest. It answers every request line with an
// identification string, never with an attestation token, and prints a reading every 2 s.
// The gateway reaches it through the PC (host/serial_bridge.py --tty <Uno port> --port 7445).

const unsigned long PERIOD_MS = 2000;
unsigned long last = 0;
String line;

void setup() {
  Serial.begin(115200);
  Serial.println(F("LEGACY-SENSOR uno v1 ready (no attestation support)"));
}

void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (line.length()) {
        Serial.print(F("LEGACY-SENSOR uno v1 cannot attest; request was: "));
        Serial.println(line.substring(0, 12));
        line = "";
      }
    } else if (line.length() < 80) {
      line += c;
    }
  }
  if (millis() - last >= PERIOD_MS) {
    last = millis();
    Serial.print(F("SENSOR a0="));
    Serial.println(analogRead(A0));
  }
}
