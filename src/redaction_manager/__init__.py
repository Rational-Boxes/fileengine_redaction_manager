# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Offsite redaction, on the backup account.

See design_documents/PROPOSAL_offsite_redaction.md. Four properties govern every
change in this repository:

* It runs on the BACKUP account and has no route to the deployment. The request
  it acts on arrives because a human carried it here.
* It is single-purpose. It briefly holds the only credential in the estate that
  can destroy backup history, so every feature that is not redaction is more
  code within reach of that credential.
* It runs on demand and stops. It does not hold the credential; it assumes the
  break-glass role through STS, MFA-required, with a short session.
* It never runs unattended — including the execution after the hold period,
  because an unattended executor is an automated deletion path with a delay on
  it.
"""

__version__ = "0.1.0"
