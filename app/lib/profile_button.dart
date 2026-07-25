// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The account button in the top-right corner: who you are signed in as, plus
// switching accounts and signing out.

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
          tooltip: appState.username,
          offset: const Offset(0, 46),
          color: UmbraColors.surfaceHigh,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          onSelected: (value) {
            switch (value) {
              case 'switch':
                appState.signOut();
                break;
              case 'signout':
                appState.signOut();
                break;
              case 'new':
                appState.signOut();
                appState.startNewAccountFlow();
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
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                CircleAvatar(
                  radius: 15,
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
                              fontSize: 13))
                      : null,
                ),
                const SizedBox(width: 8),
                Text(appState.username,
                    style: TextStyle(
                        color: UmbraColors.textPrimary, fontWeight: FontWeight.w600, fontSize: 13)),
                Icon(Icons.arrow_drop_down, color: UmbraColors.textMuted),
              ],
            ),
          ),
        );
      },
    );
  }
}
