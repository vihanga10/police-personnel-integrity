# Officer detail navigation

Open details previously displayed the workspace after the entire paginated table without bringing it into view. This update hides the officer selector while opening a profile, focuses its name, and brings the workspace into view immediately. Loading and errors are visible in that workspace. Back to officers restores the existing table, filters and page without a new directory request. Personal and service sections appear first and expand by default. Other source datasets remain collapsible.

This frontend-only update uses the existing 6596 imported source profiles. It does not alter accounts, scopes, private stores, source datasets, profile generations, journals or chains. No full audit or dataset import is required.

Stop HTTPS with Ctrl+C. Extract into Downloads and run:

```bash
bash "$HOME/Downloads/application-officer-navigation-fix/run-update.sh"
```

The guarded installer requires the all-officer-profile source at 71cdb062077a792272f119746b66a8b3b2c8a1bd or a compatible clean descendant. It verifies exact prerequisites and refuses incompatible edits or partial installs. The script runs npm tests and commits only this reviewed update.

Restart the existing HTTPS command, reload the browser page and sign in again. Open the scoped officer table and press Open details. The table should hide and the profile should be shown immediately. Back to officers restores your list. If a server-side denial or failure remains, the error is now visible under the selected officer name; share that text and the nearby backend error type, without credentials.

44 DOM tests passed, including immediate navigation/focus, returning to the table, visible failures, default expanded personal/service sections, privacy clearing and late-response protection. Actual graphical rendering and the private Mac request remain to be checked after installation.
