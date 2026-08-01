// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The account button at the bottom of the left bar: who you are signed in as,
// plus switching accounts and signing out. It is deliberately just the avatar —
// the bar is narrow, and the name is one hover (or one click) away.

import 'dart:async';

import 'package:flutter/material.dart';

import 'l10n.dart';
import 'mock.dart';
import 'theme.dart';

class ProfileButton extends StatelessWidget {
  const ProfileButton({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: appState,
      builder: (context, _) {
        final picture = appState.myPicture();
        return PopupMenuButton<String>(
          tooltip: '@${appState.username}',
          // The bar sits on the left edge, so the menu opens up and to the side.
          offset: const Offset(56, -20),
          color: UmbraColors.surfaceHigh,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          // All three end the session, which ends the process — see
          // `AppState.signOut`. What differs is only what the replacement opens
          // on, so "add an account" has to say so before we go.
          onSelected: (value) {
            switch (value) {
              case 'switch':
              case 'signout':
                unawaited(appState.signOut());
                break;
              case 'new':
                unawaited(appState.signOut(newAccount: true));
                break;
            }
          },
          itemBuilder: (context) => [
            PopupMenuItem<String>(
              enabled: false,
              child: Row(
                children: [
                  CircleAvatar(
                    radius: 16,
                    backgroundColor: UmbraColors.surface,
                    backgroundImage: picture.isNotEmpty ? MemoryImage(picture) : null,
                    child: picture.isEmpty
                        ? Text(
                            appState.username.isEmpty
                                ? '?'
                                : appState.username.characters.first.toUpperCase(),
                            style: TextStyle(
                                color: UmbraColors.accent, fontWeight: FontWeight.w700))
                        : null,
                  ),
                  const SizedBox(width: 10),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text('@${appState.username}',
                          style: TextStyle(
                              color: UmbraColors.textPrimary, fontWeight: FontWeight.w600)),
                      Text(appState.userCode,
                          style: TextStyle(
                              color: UmbraColors.textMuted,
                              fontSize: 11,
                              fontFamily: 'monospace')),
                    ],
                  ),
                ],
              ),
            ),
            const PopupMenuDivider(),
            PopupMenuItem<String>(
              value: 'switch',
              child: Row(children: [
                Icon(Icons.switch_account, size: 18, color: UmbraColors.textMuted),
                const SizedBox(width: 10),
                Text(L.t('accounts.switch')),
              ]),
            ),
            PopupMenuItem<String>(
              value: 'new',
              child: Row(children: [
                Icon(Icons.person_add_alt, size: 18, color: UmbraColors.textMuted),
                const SizedBox(width: 10),
                Text(L.t('accounts.add')),
              ]),
            ),
            PopupMenuItem<String>(
              value: 'signout',
              child: Row(children: [
                Icon(Icons.logout, size: 18, color: UmbraColors.danger),
                const SizedBox(width: 10),
                Text(L.t('accounts.signOut'),
                    style: TextStyle(color: UmbraColors.danger)),
              ]),
            ),
          ],
          child: Padding(
            padding: const EdgeInsets.all(8),
            child: CircleAvatar(
              radius: 16,
              backgroundColor: UmbraColors.surfaceHigh,
              backgroundImage: picture.isNotEmpty ? MemoryImage(picture) : null,
              child: picture.isEmpty
                  ? Text(
                      appState.username.isEmpty
                          ? '?'
                          : appState.username.characters.first.toUpperCase(),
                      style: TextStyle(
                          color: UmbraColors.accent,
                          fontWeight: FontWeight.w700,
                          fontSize: 14))
                  : null,
            ),
          ),
        );
      },
    );
  }
}
