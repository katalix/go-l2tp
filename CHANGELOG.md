## v0.18

- Handle L2TPv2 SLI and WEN messages.  The former has caused some issues for
  users connecting to certain server implementations.  This release updates
  kl2tpd to do the same as xl2tpd and accept the SLI message but ignore the
  ACCM AVP.

- Improve logging of data frames received in userspace.  This can occur if kl2tpd
  receives the first PPP LCP frame for a session in advance of the ICCN ACK,
  and leads to confusing error messages from kl2tpd.  Catch the issue earlier in
  the parsing process by checking the L2TP header message type bit before doing
  anything else.

## v0.17

- Skip L2TPIP6 transport test, which is now failing in Debian/Ubuntu due to
  a kernel regression which has been backported into various stable kernels.

## v0.1.6

- Fix up manpage sections in markdown/pandoc metadata.

## v0.1.5

- Fix up manpage install location.

## v0.1.4

- Fix up manpage roff syntax.

## v0.1.3

- Documentation spelling fix.

## v0.1.2

- Skip IP encap transport tests when the host lacks protocol support.

## v0.1.1

- Add manpages as a helper for distro packagers.

## v0.1.0

- Initial unstable release.
