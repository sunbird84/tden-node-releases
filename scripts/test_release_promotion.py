import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from candidate_metadata import ARCHIVE, existing_release_action, verify_release_assets


class ReleasePromotionTests(unittest.TestCase):
    def test_only_two_existing_release_transitions_are_allowed(self):
        for channel in ("preview", "stable"):
            for draft in (False, True):
                for preview in (False, True):
                    with self.subTest(channel=channel, draft=draft, preview=preview):
                        release = {"isDraft": draft, "isPrerelease": preview}
                        expected = {("preview", True, True): "resume_preview",
                                    ("stable", False, True): "promote_preview"}.get((channel, draft, preview))
                        if expected:
                            self.assertEqual(existing_release_action(channel, release), expected)
                        else:
                            with self.assertRaises(ValueError):
                                existing_release_action(channel, release)

    def test_invalid_metadata_cannot_promote(self):
        for release in (None, {}, {"isDraft": 0, "isPrerelease": True},
                        {"isDraft": False, "isPrerelease": "true"}):
            with self.subTest(release=release), self.assertRaises(ValueError):
                existing_release_action("stable", release)
        with self.assertRaises(ValueError):
            existing_release_action("other", {"isDraft": False, "isPrerelease": True})

    def test_exact_assets_required_before_metadata_promotion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = []
            for name in (ARCHIVE, ARCHIVE + ".sha256", "candidate-build.json"):
                data = ("original " + name).encode()
                (root / name).write_bytes(data)
                assets.append(dict(name=name, state="uploaded", size=len(data),
                                   digest="sha256:" + hashlib.sha256(data).hexdigest()))
            verify_release_assets(assets, root)
            mutations = [assets[:-1], assets + [assets[0]], [assets[0], assets[0], assets[2]]]
            for key, value in (("digest", "sha256:" + "0" * 64), ("size", 0),
                               ("state", "new"), ("name", "other")):
                changed = copy.deepcopy(assets)
                changed[0][key] = value
                mutations.append(changed)
            for changed in mutations:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    verify_release_assets(changed, root)
            (root / ARCHIVE).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                verify_release_assets(assets, root)


if __name__ == "__main__":
    unittest.main()
