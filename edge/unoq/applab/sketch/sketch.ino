// AttackGraph Lens edge app (MCU side): shows the organisation's top incident priority on the 8x13 LED matrix.
// level 0 = Low (one dot), 1 = Moderate, 2 = High, 3 = Critical (full bars, blinking).
#include <Arduino_RouterBridge.h>
#include <Arduino_LED_Matrix.h>

Arduino_LED_Matrix matrix;
uint8_t frame[104];
volatile int level = 0;
int shown = -1;
bool blinkOn = true;
unsigned long lastBlink = 0;

void render(int lv, bool on) {
  for (int r = 0; r < 8; r++) {
    for (int c = 0; c < 13; c++) {
      int v = 0;
      if (on) {
        if (lv <= 0) v = (r == 7 && c == 6);
        else v = (r >= 8 - (lv * 2 + 2)) && (c % 3 != 2);
      }
      frame[r * 13 + c] = v;
    }
  }
  matrix.draw(frame);
}

void set_level(int lv) {
  if (lv < 0) lv = 0;
  if (lv > 3) lv = 3;
  level = lv;
}

void setup() {
  matrix.begin();
  matrix.setGrayscaleBits(1);
  Bridge.begin();
  Bridge.provide("set_level", set_level);
  render(0, true);
}

void loop() {
  int lv = level;
  if (lv != shown) {
    shown = lv;
    blinkOn = true;
    render(lv, true);
  }
  if (lv == 3 && millis() - lastBlink > 400) {
    lastBlink = millis();
    blinkOn = !blinkOn;
    render(3, blinkOn);
  }
  delay(20);
}
