This is a checklist for doing Sequoia releases.

 0. Starting from origin/master, create a branch XXX for the release.
 1. For all 'Cargo.toml's: Bump version = "XXX".
       - Only do this for non-released crates and those with changes
         relative to the last released version.
 2. For all 'Cargo.toml's: Bump documentation = "https://.../XXX/...".
 3. For all 'Cargo.toml's: Bump intra-workspace dependencies.
 4. Run 'make sanity-check-versions'.
       - This simple check fails if not all versions are in sync.
 5. Run 'cargo update && make check'.
 6. Make a commit with the message "Release XXX.".
       - Push this to a branch on gitlab with the word 'windows' in
         it, e.g. XXX-also-test-on-windows-please, and create a merge
         request.
 7. Make a tag vXXX with the message "Release XXX." signed with an
    offline-key.
 8. Make a clean clone of the repository.
 9. For the following crates, cd into the directory, and do 'cargo
    publish':
       - buffered-reader
       - openpgp
       - sop
       - sqv
10. In case of errors, correct them, and go back to 6.
11. Merge the branch to master by merging the merge request created in
    step 6, push the tag.
12. Regenerate docs.sequoia-pgp.org.
13. Announce the release.
       - IRC
       - mailing list
       - web site
