/// Canonical disclaimer text, mirroring `DISCLAIMER` in
/// `backend/app/schemas/common.py`. Kept visible on every report.
library;

const String disclosureText =
    'CyberShield produces automated, evidence-based risk assessments. It cannot '
    'guarantee that an object is safe or malicious: false positives and false '
    'negatives are possible. Treat the verdict as one input into your security '
    'decision, alongside user judgement and other controls.';

/// Platform limit callout for file/APK reports.
const String staticOnlyNote =
    'Static-only analysis — the file is never executed, mounted, unpacked-to-run '
    'or installed. Anything requiring execution is out of scope by design, so no '
    'runtime behaviour is observed.';