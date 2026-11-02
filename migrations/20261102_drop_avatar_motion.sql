-- The portrait animation became the app's fixed look (see AppAvatar.vue and
-- .np-avatar-motion in assets/styles.css), so the per-account switch and its
-- column are gone. The column is inert if left behind, but dropping it keeps
-- the schema honest about what the app actually uses.
ALTER TABLE user_settings DROP COLUMN IF EXISTS avatar_motion;
