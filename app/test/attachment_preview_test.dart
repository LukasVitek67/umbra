// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `sniff` decides which received files reach an image decoder, so it is worth
// pinning down: a peer chooses both the name and the content, and the name must
// never be what gets believed.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:nullchat/attachment_preview.dart';

Uint8List bytes(List<int> head, {int pad = 64}) {
  final out = Uint8List(head.length + pad);
  out.setAll(0, head);
  return out;
}

void main() {
  test('pictures are recognised by their bytes', () {
    expect(sniff(bytes([0x89, 0x50, 0x4E, 0x47])), MediaKind.image); // PNG
    expect(sniff(bytes([0xFF, 0xD8, 0xFF])), MediaKind.image); // JPEG
    expect(sniff(bytes([0x42, 0x4D])), MediaKind.image); // BMP
    expect(sniff(bytes([0x47, 0x49, 0x46, 0x38])), MediaKind.gif);

    final webp = bytes([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]);
    expect(sniff(webp), MediaKind.image);
  });

  test('video and audio are named but never decoded here', () {
    final mp4 = bytes([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70]);
    expect(sniff(mp4), MediaKind.media);
    expect(sniff(bytes([0x1A, 0x45, 0xDF, 0xA3])), MediaKind.media); // WebM
    expect(sniff(bytes([0x49, 0x44, 0x33])), MediaKind.media); // MP3
  });

  test('a file that lies about being a picture is not decoded', () {
    // What a hostile sender would try: an executable called holiday.jpg. The
    // name is not consulted, so this stays an ordinary attachment.
    expect(sniff(bytes([0x4D, 0x5A, 0x90, 0x00])), MediaKind.other); // PE
    expect(sniff(bytes([0x7F, 0x45, 0x4C, 0x46])), MediaKind.other); // ELF
    expect(sniff(bytes([0x25, 0x50, 0x44, 0x46])), MediaKind.other); // PDF
    expect(sniff(Uint8List(0)), MediaKind.other);
    expect(sniff(bytes([0x47, 0x49])), MediaKind.other); // truncated GIF magic
  });

  test('the preview cap stays well under what a decoder should be fed', () {
    expect(kPreviewMaxBytes, lessThanOrEqualTo(16 * 1024 * 1024));
  });
}
