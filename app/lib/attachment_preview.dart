// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Inline previews for received files.
//
// Three rules shape this, and they are the reason it does not simply hand every
// file to a decoder:
//
// 1. **The bytes never touch the disk unsealed.** Attachments are stored
//    encrypted; a preview decrypts into memory, shows it, and forgets it. The
//    only readable copy is still the one the user asks for with "Save file".
//
// 2. **The file's own bytes decide, not its name.** `holiday.jpg` can be
//    anything at all. What is decoded is chosen by the magic bytes, so a file
//    that lies about itself is shown as an ordinary attachment instead.
//
// 3. **Big files are not previewed.** Image decoders are a long-standing source
//    of memory-corruption bugs — the 2023 WebP flaw needed no interaction —
//    and a decoder is the one place where a peer's bytes get interpreted. A
//    hard cap keeps the exposure to something a person actually wants to see.

import 'dart:typed_data';

import 'package:flutter/material.dart';

import 'l10n.dart';
import 'mock.dart';
import 'theme.dart';

/// What a file turned out to be, judged by its first bytes.
enum MediaKind {
  /// Still image formats Flutter can decode.
  image,

  /// An animated GIF: the same decoder, but worth its own label because the
  /// preview animates and that is the whole point of sending one.
  gif,

  /// Video or audio. Recognised so the tile can say so, never decoded here:
  /// playing it would mean writing a decrypted copy somewhere.
  media,

  /// Anything else, including files whose bytes do not match their name.
  other,
}

/// Above this, a file gets a tile instead of a picture. 12 MB is generous for a
/// photo and far below what would make decoding a comfortable place to attack.
const int kPreviewMaxBytes = 12 * 1024 * 1024;

/// Extensions people recognise as "a photo, a video, a GIF" — the ones that do
/// not need their filename announced above them.
///
/// This decides *presentation* only. What actually reaches a decoder is still
/// chosen by the file's own header, so a name here buys a sender nothing.
const Set<String> kMediaExtensions = {
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic', 'heif',
  'mp4', 'mov', 'm4v', 'webm', 'mkv', 'avi', '3gp',
};

/// Is this the kind of file a chat app shows rather than lists?
bool looksLikeMedia(String? name) {
  if (name == null) return false;
  final dot = name.lastIndexOf('.');
  if (dot < 0 || dot == name.length - 1) return false;
  return kMediaExtensions.contains(name.substring(dot + 1).toLowerCase());
}

/// Identify a file from its leading bytes.
///
/// Deliberately small: a handful of formats that Flutter can render, plus the
/// container headers worth naming. Everything unrecognised is `other`, which is
/// the safe answer.
MediaKind sniff(Uint8List bytes) {
  bool starts(List<int> magic, {int at = 0}) {
    if (bytes.length < at + magic.length) return false;
    for (var i = 0; i < magic.length; i++) {
      if (bytes[at + i] != magic[i]) return false;
    }
    return true;
  }

  if (starts([0x47, 0x49, 0x46, 0x38])) return MediaKind.gif; // GIF8
  if (starts([0x89, 0x50, 0x4E, 0x47])) return MediaKind.image; // PNG
  if (starts([0xFF, 0xD8, 0xFF])) return MediaKind.image; // JPEG
  if (starts([0x42, 0x4D])) return MediaKind.image; // BMP
  // RIFF....WEBP — animated or still, Flutter decodes both.
  if (starts([0x52, 0x49, 0x46, 0x46]) && starts([0x57, 0x45, 0x42, 0x50], at: 8)) {
    return MediaKind.image;
  }
  // ISO base media (MP4, MOV, M4A): "....ftyp"
  if (starts([0x66, 0x74, 0x79, 0x70], at: 4)) return MediaKind.media;
  if (starts([0x1A, 0x45, 0xDF, 0xA3])) return MediaKind.media; // Matroska/WebM
  if (starts([0x4F, 0x67, 0x67, 0x53])) return MediaKind.media; // Ogg
  if (starts([0x49, 0x44, 0x33])) return MediaKind.media; // MP3 with ID3
  return MediaKind.other;
}

/// An image or GIF shown in the bubble, sized so a tall photo cannot take over
/// the conversation. Tapping opens it full screen.
class AttachmentPreview extends StatefulWidget {
  const AttachmentPreview({
    super.key,
    required this.path,
    required this.name,
    required this.size,
    this.onShown,
  });

  final String path;
  final String name;
  final int? size;

  /// Called once it is known whether a picture is actually on screen. The
  /// bubble uses it to drop the filename above a photo: showing
  /// `IMG_20260731.jpg` over the photo itself is noise, but a file that turned
  /// out not to be viewable still needs its name.
  final void Function(bool showing)? onShown;

  @override
  State<AttachmentPreview> createState() => _AttachmentPreviewState();
}

class _AttachmentPreviewState extends State<AttachmentPreview> {
  Uint8List? _bytes;
  MediaKind _kind = MediaKind.other;
  bool _tooBig = false;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void didUpdateWidget(AttachmentPreview old) {
    super.didUpdateWidget(old);
    if (old.path != widget.path) _load();
  }

  Future<void> _load() async {
    // The size the sender announced is enough to skip the decrypt entirely.
    if ((widget.size ?? 0) > kPreviewMaxBytes) {
      if (mounted) {
        setState(() {
          _tooBig = true;
          _loading = false;
        });
      }
      return;
    }
    final bytes = await appState.attachmentBytes(widget.path);
    if (!mounted) return;
    setState(() {
      _loading = false;
      if (bytes == null) return;
      if (bytes.length > kPreviewMaxBytes) {
        _tooBig = true;
        return;
      }
      _kind = sniff(bytes);
      if (_kind == MediaKind.image || _kind == MediaKind.gif) _bytes = bytes;
    });
    widget.onShown?.call(_bytes != null);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const SizedBox(
        height: 2,
        child: LinearProgressIndicator(minHeight: 2),
      );
    }
    final bytes = _bytes;
    if (bytes == null) {
      // Not an image, too big, or unreadable: the file tile already says
      // everything useful, so add only what it does not.
      if (_kind == MediaKind.media) {
        return _Note(icon: Icons.play_circle_outline, text: L.t('file.mediaNote'));
      }
      if (_tooBig) {
        return _Note(icon: Icons.image_not_supported_outlined, text: L.t('file.tooBig'));
      }
      return const SizedBox.shrink();
    }

    return Padding(
      padding: EdgeInsets.zero,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(10),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxHeight: 260, maxWidth: 340),
          child: InkWell(
            onTap: () => _openFull(context, bytes, widget.name),
            child: Image.memory(
              bytes,
              fit: BoxFit.cover,
              // A corrupt or hostile file must not take the conversation with
              // it: the bubble falls back to the plain tile.
              errorBuilder: (_, _, _) =>
                  _Note(icon: Icons.broken_image_outlined, text: L.t('file.badImage')),
            ),
          ),
        ),
      ),
    );
  }
}

/// Open an attachment full screen from outside the bubble (the message menu).
///
/// Decrypts on demand and shows nothing if the file is not a picture — there is
/// no viewer here for anything else, and writing a copy somewhere so the system
/// could open it is exactly what this app does not do.
Future<void> openAttachmentFullScreen(
  BuildContext context,
  String path,
  String name,
) async {
  final bytes = await appState.attachmentBytes(path);
  if (!context.mounted) return;
  if (bytes == null || bytes.length > kPreviewMaxBytes) {
    appState.showInAppNotice(name, L.t('file.tooBig'));
    return;
  }
  final kind = sniff(bytes);
  if (kind != MediaKind.image && kind != MediaKind.gif) {
    appState.showInAppNotice(
      name,
      kind == MediaKind.media ? L.t('file.mediaNote') : L.t('file.badImage'),
    );
    return;
  }
  if (!context.mounted) return;
  _openFull(context, bytes, name);
}

void _openFull(BuildContext context, Uint8List bytes, String name) {
  showDialog<void>(
    context: context,
    barrierColor: Colors.black87,
    builder: (ctx) => Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: const EdgeInsets.all(24),
      child: Stack(
        children: [
          InteractiveViewer(
            maxScale: 6,
            child: Center(child: Image.memory(bytes)),
          ),
          Positioned(
            top: 0,
            right: 0,
            child: IconButton(
              tooltip: L.t('common.close'),
              icon: const Icon(Icons.close, color: Colors.white),
              onPressed: () => Navigator.of(ctx).pop(),
            ),
          ),
        ],
      ),
    ),
  );
}

class _Note extends StatelessWidget {
  const _Note({required this.icon, required this.text});
  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(top: 6),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: UmbraColors.textMuted),
          const SizedBox(width: 6),
          Flexible(
            child: Text(text,
                style: TextStyle(color: UmbraColors.textMuted, fontSize: 11)),
          ),
        ],
      ),
    );
  }
}
