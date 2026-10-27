// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import android.Manifest;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.Handler;
import android.os.Looper;

import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import io.github.xer0bit.nullveil.databinding.ActivityMainBinding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {
    private static final String[] PLACES = {"Null Island", "Reykjavik", "Tokyo", "Buenos Aires", "McMurdo Station", "Custom"};
    private static final double[][] COORDS = {{0, 0}, {64.1466, -21.9426}, {35.6762, 139.6503}, {-34.6037, -58.3816}, {-77.846, 166.676}};

    private ActivityMainBinding b;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final List<Object> rows = new ArrayList<>();
    private final List<AppRow> apps = new ArrayList<>();
    private final List<Object> watchRows = new ArrayList<>();
    private ArrayAdapter<Object> shieldAdapter;
    private ArrayAdapter<Object> watchAdapter;
    private final Map<String, Drawable.ConstantState> iconCache = new java.util.HashMap<>();
    private final Map<String, String> labelCache = new java.util.HashMap<>();
    private Map<String, AppSum> lastSums = new LinkedHashMap<>();
    private int filter; // 0 all, 1 blocked, 2 suspicious (flagged but let through)
    private ArrayAdapter<AppRow> appsAdapter;
    private final List<Step> steps = new ArrayList<>();
    private ArrayAdapter<Step> setupAdapter;
    private ObjectAnimator pulse;
    private int shownVersion = -1;
    private String shownSetup = "";

    private static final int BAD = 0, OK = 1, INFO = 2;

    private static final class Step {
        final String title, detail;
        final int state;
        final boolean required;
        final Runnable fix;

        Step(String title, String detail, int state, boolean required, Runnable fix) {
            this.title = title;
            this.detail = detail;
            this.state = state;
            this.required = required;
            this.fix = fix;
        }
    }

    private final ActivityResultLauncher<String> micPerm = registerForActivityResult(new ActivityResultContracts.RequestPermission(), granted -> {
        if (granted) startGuard();
        render();
    });

    private final ActivityResultLauncher<String> notifPerm =
            registerForActivityResult(new ActivityResultContracts.RequestPermission(), granted -> render());

    private static final class AppRow {
        final String label, pkg;
        final int perms;

        AppRow(String label, String pkg, int perms) {
            this.label = label;
            this.pkg = pkg;
            this.perms = perms;
        }
    }

    private final ActivityResultLauncher<Intent> consent = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            r -> {
                if (r.getResultCode() == RESULT_OK) startService(new Intent(this, VeilService.class));
            });

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            render();
            ui.postDelayed(this, 700);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());
        Settings.applyRules(this);

        b.tabShield.setOnClickListener(v -> tab(0));
        b.tabWatch.setOnClickListener(v -> tab(1));
        b.tabApps.setOnClickListener(v -> tab(2));
        b.tabGhost.setOnClickListener(v -> tab(3));
        b.tabSetup.setOnClickListener(v -> tab(4));
        b.setupHint.setOnClickListener(v -> tab(4));
        b.fAll.setOnClickListener(v -> setFilter(0));
        b.fBlocked.setOnClickListener(v -> setFilter(1));
        b.fSusp.setOnClickListener(v -> setFilter(2));
        b.fClear.setOnClickListener(v -> {
            Events.clear();
            render();
        });
        b.ring.setOnClickListener(v -> toggleVeil());
        b.guard.setOnClickListener(v -> toggleGuard());
        b.dot.setOnClickListener(v -> {
            Settings.cycleDot(this);
            render();
        });
        b.strict.setOnClickListener(v -> {
            Settings.toggleStrict(this);
            render();
        });
        b.rules.setOnLongClickListener(v -> {
            Settings.clearRules(this);
            Toast.makeText(this, "Overrides cleared", Toast.LENGTH_SHORT).show();
            return true;
        });

        shieldAdapter = new ArrayAdapter<Object>(this, 0, rows) {
            @Override
            public View getView(int i, View v, ViewGroup parent) {
                return shieldRow(rows.get(i));
            }
        };
        b.shieldList.setAdapter(shieldAdapter);
        b.shieldList.setOnItemClickListener((p, v, i, id) -> tab(1)); // act on catches in WATCH
        watchAdapter = new ArrayAdapter<Object>(this, 0, watchRows) {
            @Override
            public View getView(int i, View v, ViewGroup parent) {
                return watchRow(watchRows.get(i));
            }
        };
        b.watchList.setAdapter(watchAdapter);

        appsAdapter = new ArrayAdapter<AppRow>(this, 0, apps) {
            @Override
            public View getView(int i, View v, ViewGroup parent) {
                AppRow a = apps.get(i);
                AppSum t = lastSums.get(a.pkg);
                String flags = ((a.perms & Watch.MIC) != 0 ? "MIC " : "") + ((a.perms & Watch.CAM) != 0 ? "CAM " : "")
                        + ((a.perms & Watch.LOC) != 0 ? "LOC" : "");
                boolean hot = t != null && t.blocked > 0;
                TextView name = plain(a.label, getColor(hot ? R.color.alarm : R.color.fg), 13);
                TextView sub = plain((flags.trim().isEmpty() ? "no mic, camera or location" : "can use: " + flags.trim())
                        + (t == null ? "" : "\nNullveil: " + t.blocked + " blocked · " + t.suspicious + " suspicious"), getColor(R.color.dim), 11);
                sub.setPadding(0, dp(3), 0, 0);
                return appBox(a.pkg, name, sub, null);
            }
        };
        b.appsList.setAdapter(appsAdapter);
        setupAdapter = new ArrayAdapter<Step>(this, 0, steps) {
            @Override
            public View getView(int i, View v, ViewGroup parent) {
                return stepRow(steps.get(i));
            }
        };
        b.setupList.setAdapter(setupAdapter);
        b.setupList.setOnItemClickListener((p, v, i, id) -> steps.get(i).fix.run());
        b.appsList.setOnItemClickListener((p, v, i, id) -> showApp(apps.get(i).pkg)); // Nullveil's own view, not Android settings

        b.place.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, PLACES));
        b.place.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> p, View v, int i, long id) {
                if (i < COORDS.length) {
                    b.lat.setText(String.valueOf(COORDS[i][0]));
                    b.lon.setText(String.valueOf(COORDS[i][1]));
                }
            }

            @Override
            public void onNothingSelected(android.widget.AdapterView<?> p) {}
        });
        b.ghost.setOnClickListener(v -> toggleGhost());
        b.devOptions.setOnClickListener(v -> {
            if (!mockLocationApp()) ghostHelp();
            else tab(4);
        });
        tab(getIntent().getIntExtra("tab", 0));
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!GhostService.running && mockLocationApp()) GhostService.cleanup(this);
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(tick);
        if (pulse != null) {
            pulse.cancel();
            pulse = null;
        }
    }

    private void tab(int t) {
        View[] panels = {b.panelShield, b.panelWatch, b.panelApps, b.panelGhost, b.panelSetup};
        TextView[] tabs = {b.tabShield, b.tabWatch, b.tabApps, b.tabGhost, b.tabSetup};
        for (int i = 0; i < tabs.length; i++) {
            panels[i].setVisibility(i == t ? View.VISIBLE : View.GONE);
            tabs[i].setTextColor(getColor(i == t ? R.color.acid : R.color.dim));
            tabs[i].setBackgroundResource(i == t ? R.drawable.tab_on : 0);
        }
        if (t == 2) loadApps();
    }

    private void toggleVeil() {
        if (Events.running) {
            startService(new Intent(this, VeilService.class).setAction(VeilService.ACTION_STOP));
            return;
        }
        Intent ask = VpnService.prepare(this); // null once the user has already approved
        if (ask != null) consent.launch(ask);
        else startService(new Intent(this, VeilService.class));
    }

    /**
     * Ghost mode needs one Android app-op that no normal app can grant itself: either you pick Nullveil as the
     * "mock location app" in Developer options, or Android's shell grants it. There is no third way without root.
     */
    private void ghostHelp() {
        String cmd = "adb shell appops set " + getPackageName() + " android:mock_location allow";
        new AlertDialog.Builder(this)
                .setTitle("Unlock Ghost mode (one time)")
                .setMessage("Android lets an app show other apps a different position only after you allow it once. "
                        + "No app can skip this without root; it is an Android security rule.\n\n"
                        + "A) On the phone: Developer options > Select mock location app > Nullveil.\n"
                        + "Do NOT choose \"No application\" and do not switch Developer options off: that locks Ghost mode again.\n\n"
                        + "B) From a computer with USB debugging:\n" + cmd + "\n\nIt stays on afterwards.")
                .setNeutralButton("OPEN DEVELOPER OPTIONS", (d, w) -> {
                    try {
                        startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS));
                    } catch (ActivityNotFoundException e) {
                        Toast.makeText(this, "Turn on Developer options: tap Build number 7 times", Toast.LENGTH_LONG).show();
                        open(new Intent(android.provider.Settings.ACTION_DEVICE_INFO_SETTINGS));
                    }
                })
                .setPositiveButton("COPY COMMAND", (d, w) -> {
                    getSystemService(android.content.ClipboardManager.class).setPrimaryClip(android.content.ClipData.newPlainText("command", cmd));
                    Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("CLOSE", null)
                .show();
    }

    private void startGuard() {
        startForegroundService(new Intent(this, MicGuardService.class));
    }

    private void toggleGuard() {
        if (MicGuardService.running) {
            startService(new Intent(this, MicGuardService.class).setAction(MicGuardService.ACTION_STOP));
        } else if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            startGuard();
        } else {
            micPerm.launch(Manifest.permission.RECORD_AUDIO); // Nullveil needs the mic itself in order to hold it
        }
    }

    private void toggleGhost() {
        if (GhostService.running) {
            startService(new Intent(this, GhostService.class).setAction(GhostService.ACTION_STOP));
            return;
        }
        try {
            double lat = Double.parseDouble(b.lat.getText().toString());
            double lon = Double.parseDouble(b.lon.getText().toString());
            if (Math.abs(lat) > 90 || Math.abs(lon) > 180) throw new NumberFormatException();
            startForegroundService(new Intent(this, GhostService.class).putExtra(GhostService.LAT, lat).putExtra(GhostService.LON, lon));
        } catch (NumberFormatException e) {
            Toast.makeText(this, "Latitude -90..90, longitude -180..180", Toast.LENGTH_SHORT).show();
        }
    }

    /** Apps Nullveil caught, then apps holding mic, camera or location. Tap opens Nullveil's own view of the app. */
    private void loadApps() {
        apps.clear();
        PackageManager pm = getPackageManager();
        for (PackageInfo pi : pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            ApplicationInfo ai = pi.applicationInfo;
            boolean system = ai != null && (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0 && (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
            int perms = Watch.permsOf(pi);
            boolean tracked = lastSums.containsKey(pi.packageName);
            if (ai != null && !system && (perms != 0 || tracked) && !pi.packageName.equals(getPackageName())) {
                apps.add(new AppRow(String.valueOf(ai.loadLabel(pm)), pi.packageName, perms));
            }
        }
        apps.sort((x, y) -> {
            int tx = trackedScore(x.pkg), ty = trackedScore(y.pkg);
            if (tx != ty) return ty - tx; // apps Nullveil caught first
            int px = Integer.bitCount(x.perms), py = Integer.bitCount(y.perms);
            return px != py ? py - px : x.label.compareToIgnoreCase(y.label);
        });
        appsAdapter.notifyDataSetChanged();
    }

    private TextView line(String text, int color) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextColor(color);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextSize(11);
        t.setPadding(28, 22, 28, 22);
        t.setBackgroundResource(R.drawable.card);
        return t;
    }

    private View shieldRow(Object o) {
        if (o instanceof String) {
            TextView h = line((String) o, getColor(R.color.acid));
            h.setBackground(null);
            h.setLetterSpacing(0.15f);
            h.setPadding(4, 18, 0, 4);
            return h;
        }
        if (o instanceof Events.Caught) {
            Events.Caught c = (Events.Caught) o;
            return line("✕ " + c.app + "  x" + c.count + "\n   " + c.lastDomain + "\n   " + c.why, getColor(R.color.alarm));
        }
        if (o instanceof MicWatch.Entry) {
            MicWatch.Entry m = (MicWatch.Entry) o;
            java.text.DateFormat f = java.text.DateFormat.getTimeInstance(java.text.DateFormat.MEDIUM);
            String span = f.format(new java.util.Date(m.start)) + (m.end == 0 ? "  still recording" : "  for " + Math.max(1, (m.end - m.start) / 1000) + "s");
            return line((m.silenced ? "✓ " : m.suspicious ? "✕ " : "· ") + span + "\n   " + m.where + (m.silenced ? "\n   Mic Guard: the app heard silence" : ""),
                    getColor(m.silenced ? R.color.acid : m.suspicious ? R.color.alarm : R.color.dim));
        }
        Events.Entry e = (Events.Entry) o;
        return line((e.blocked ? "✕ " : "· ") + e.domain + "\n   " + e.app + (e.blocked ? "  " + e.why : ""),
                getColor(e.blocked ? R.color.alarm : R.color.dim));
    }

    private void render() {
        boolean on = Events.running;
        b.ring.setBackgroundResource(on ? R.drawable.ring_on : R.drawable.ring_off);
        b.ring.setText(on ? "STOP" : "START");
        b.status.setText(on ? "VEILED" : "EXPOSED");
        b.status.setTextColor(getColor(on ? R.color.acid : R.color.alarm));
        b.sunk.setText(chip(Events.sunk.get(), "SUNK", R.color.alarm));
        b.passed.setText(chip(Events.passed.get(), "PASSED", R.color.fg));
        if (on && pulse == null) {
            pulse = ObjectAnimator.ofPropertyValuesHolder(b.ring, PropertyValuesHolder.ofFloat(View.SCALE_X, 1f, 1.05f),
                    PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f, 1.05f));
            pulse.setDuration(1400);
            pulse.setRepeatCount(ObjectAnimator.INFINITE);
            pulse.setRepeatMode(ObjectAnimator.REVERSE);
            pulse.start();
        } else if (!on && pulse != null) {
            pulse.cancel();
            pulse = null;
            b.ring.setScaleX(1f);
            b.ring.setScaleY(1f);
        }
        if (MicWatch.active) {
            b.mic.setText(MicWatch.silenced ? "mic: an app is recording and hears SILENCE ✓" : "mic: IN USE  (" + MicWatch.where + ")");
            b.mic.setTextColor(getColor(MicWatch.silenced ? R.color.acid : MicWatch.suspicious ? R.color.alarm : R.color.fg));
        } else {
            b.mic.setText(on ? "mic: idle" : "mic: not watching (turn the shield on)");
            b.mic.setTextColor(getColor(R.color.dim));
        }
        boolean guard = MicGuardService.running;
        b.guard.setText(guard ? "MIC GUARD  ON  (apps hear silence · retaken " + MicGuardService.reclaims.get() + "x)"
                : "MIC GUARD  OFF  (tap: every app hears silence)");
        b.guard.setTextColor(getColor(guard ? R.color.acid : R.color.dim));
        int dotMode = Settings.dotMode(this);
        int fb = Events.plainFallbacks.get();
        b.dot.setText(dotMode == 0 ? "ENCRYPTED DNS  OFF  (tap: choose Quad9 or Cloudflare)"
                : "ENCRYPTED DNS  ON  (TLS to " + DotClient.Resolver.values()[dotMode - 1].label
                + (fb > 0 ? ", " + fb + " plain fallbacks" : "") + ")");
        b.dot.setTextColor(getColor(dotMode != 0 ? R.color.acid : R.color.dim));
        b.strict.setText(Settings.strict(this) ? "STRICT  ON" : "STRICT  OFF");
        b.strict.setTextColor(getColor(Settings.strict(this) ? R.color.acid : R.color.dim));
        buildSteps();
        int missing = 0;
        StringBuilder sig = new StringBuilder();
        for (Step st : steps) {
            if (st.required && st.state == BAD) missing++;
            sig.append(st.state);
        }
        b.setupHint.setVisibility(missing > 0 ? View.VISIBLE : View.GONE);
        b.setupHint.setText(missing + " setup step" + (missing == 1 ? "" : "s") + " missing  [fix]");
        if (!sig.toString().equals(shownSetup)) {
            shownSetup = sig.toString();
            setupAdapter.notifyDataSetChanged();
        }
        b.rules.setText(Settings.ruleCount(this) + " rules · hold = clear");

        for (int i = 0; i < 3; i++) {
            TextView f = new TextView[]{b.fAll, b.fBlocked, b.fSusp}[i];
            f.setTextColor(getColor(i == filter ? R.color.acid : R.color.dim));
        }
        if (Events.version.get() != shownVersion) {
            shownVersion = Events.version.get();
            rows.clear();
            rows.add("LATEST CATCHES · open WATCH to act");
            int n = 0;
            for (Events.Entry e : Events.recent()) if (e.blocked && n++ < 5) rows.add(e);
            if (n == 0) rows.add("nothing caught yet");
            shieldAdapter.notifyDataSetChanged();
            buildWatch();
            watchAdapter.notifyDataSetChanged();
            appsAdapter.notifyDataSetChanged();
        }

        boolean ghostReady = mockLocationApp();
        b.devOptions.setText(ghostReady ? "ghost mode access: READY" : "ghost mode access: LOCKED   [tap to unlock]");
        b.devOptions.setTextColor(getColor(ghostReady ? R.color.acid : R.color.alarm));
        b.ghost.setBackgroundResource(GhostService.running ? R.drawable.pill_on : R.drawable.pill_off);
        b.ghost.setText(GhostService.running ? "GHOST  ON" : "GHOST  OFF");
        b.ghost.setTextColor(getColor(GhostService.running ? R.color.acid : R.color.fg));
        b.ghostStatus.setText(GhostService.error.isEmpty() ? (GhostService.running ? "apps now see the position above" : "") : GhostService.error);
    }
    private static final class AppSum {
        final String app;
        int blocked, suspicious;
        String lastDomain = "", lastWhy = "";

        AppSum(String app) {
            this.app = app;
        }
    }

    private static final class Act {
        final String label;
        final boolean on;
        final Runnable run;

        Act(String label, boolean on, Runnable run) {
            this.label = label;
            this.on = on;
            this.run = run;
        }
    }

    private static final class Card {
        final String pkg, title, sub; // pkg: app this card is about (icon, tap for details), or null
        final int color;
        final List<Act> acts;

        Card(String pkg, String title, String sub, int color, List<Act> acts) {
            this.pkg = pkg;
            this.title = title;
            this.sub = sub;
            this.color = color;
            this.acts = acts;
        }
    }

    private void setFilter(int f) {
        filter = f;
        Events.version.incrementAndGet();
        render();
    }

    /** Apps with tracking activity first (act on the whole app), then individual lookups (act on a domain). */
    private void buildWatch() {
        watchRows.clear();
        List<Events.Entry> all = Events.recent();
        Map<String, AppSum> sums = new LinkedHashMap<>();
        for (Events.Entry e : all) {
            if (!e.blocked && e.score < 3) continue;
            AppSum s = sums.computeIfAbsent(e.app, AppSum::new);
            if (e.blocked) s.blocked++;
            else s.suspicious++;
            if (s.lastDomain.isEmpty()) {
                s.lastDomain = e.domain;
                s.lastWhy = e.why;
            }
        }
        lastSums = sums;
        List<AppSum> apps = new ArrayList<>();
        for (AppSum s : sums.values()) {
            if (filter == 0 || (filter == 1 && s.blocked > 0) || (filter == 2 && s.suspicious > 0)) apps.add(s);
        }
        apps.sort((x, y) -> (y.blocked * 2 + y.suspicious) - (x.blocked * 2 + x.suspicious));
        watchRows.add("APPS WITH TRACKING ACTIVITY (" + apps.size() + ")");
        if (apps.isEmpty()) watchRows.add(Events.running ? "nothing suspicious yet" : "turn the shield on first (SHIELD tab)");
        for (AppSum s : apps) {
            boolean known = !s.app.equals("?") && !s.app.startsWith("uid:");
            int mode = Settings.appMode(this, s.app);
            List<Act> acts = new ArrayList<>();
            if (known) {
                acts.add(new Act(mode == 1 ? "LOCKED ✓" : "LOCK IN BACKGROUND", mode == 1, () -> Settings.toggleAppMode(this, s.app, 1)));
                acts.add(new Act(mode == 2 ? "TRUSTED ✓" : "TRUST", mode == 2, () -> Settings.toggleAppMode(this, s.app, 2)));
            }
            watchRows.add(new Card(known ? s.app : null, (s.blocked > 0 ? "✕ " : "◇ ") + label(s.app),
                    s.app + "\n" + s.blocked + " blocked · " + s.suspicious + " suspicious\n" + s.lastDomain + "\n" + s.lastWhy,
                    s.blocked > 0 ? R.color.alarm : R.color.fg, acts));
        }
        watchRows.add("RECENT LOOKUPS");
        int shown = 0;
        for (Events.Entry e : all) {
            boolean suspicious = !e.blocked && e.score >= 3;
            if ((filter == 1 && !e.blocked) || (filter == 2 && !suspicious)) continue;
            if (shown++ >= 60) break;
            int state = Settings.domainState(this, e.domain);
            List<Act> acts = new ArrayList<>();
            acts.add(new Act(state == 2 ? "BLOCKED ✓" : "BLOCK", state == 2, () -> Settings.toggleRule(this, e.domain, false)));
            acts.add(new Act(state == 1 ? "ALLOWED ✓" : "ALLOW", state == 1, () -> Settings.toggleRule(this, e.domain, true)));
            boolean knownApp = !e.app.equals("?") && !e.app.startsWith("uid:");
            watchRows.add(new Card(knownApp ? e.app : null, (e.blocked ? "✕ " : suspicious ? "◇ " : "· ") + e.domain + (e.score > 0 ? "   score " + e.score : ""),
                    label(e.app) + (e.why.isEmpty() ? "" : "\n" + e.why),
                    e.blocked ? R.color.alarm : suspicious ? R.color.fg : R.color.dim, acts));
        }
        if (shown == 0) watchRows.add("no lookups match this filter");
        watchRows.add("MICROPHONE");
        List<MicWatch.Entry> mic = MicWatch.recent();
        if (mic.isEmpty()) watchRows.add("no recording seen yet");
        watchRows.addAll(mic);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private TextView plain(String text, int color, int size) {
        TextView t = line(text, color);
        t.setBackground(null);
        t.setPadding(0, 0, 0, 0);
        t.setTextSize(size);
        return t;
    }

    private View watchRow(Object o) {
        if (!(o instanceof Card)) return shieldRow(o); // headers and microphone rows
        Card c = (Card) o;
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackgroundResource(R.drawable.card);
        box.setPadding(28, 22, 28, 22);
        TextView title = plain(c.title, getColor(c.color), 12);
        TextView sub = plain(c.sub, getColor(R.color.dim), 11);
        sub.setPadding(0, dp(4), 0, 0);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.addView(title);
        col.addView(sub);
        if (c.pkg != null) {
            box.addView(withIcon(c.pkg, col, 36));
            box.setOnClickListener(v -> showApp(c.pkg));
        } else {
            box.addView(col);
        }
        if (!c.acts.isEmpty()) {
            LinearLayout bar = new LinearLayout(this);
            bar.setOrientation(LinearLayout.HORIZONTAL);
            bar.setPadding(0, dp(12), 0, 0);
            for (Act a : c.acts) {
                TextView btn = plain(a.label, getColor(a.on ? R.color.acid : R.color.fg), 10);
                btn.setBackgroundResource(a.on ? R.drawable.pill_on : R.drawable.pill_off);
                btn.setGravity(android.view.Gravity.CENTER);
                btn.setPadding(dp(14), dp(9), dp(14), dp(9));
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                lp.setMarginEnd(dp(8));
                btn.setLayoutParams(lp);
                btn.setOnClickListener(v -> {
                    a.run.run();
                    Events.version.incrementAndGet();
                    render();
                });
                bar.addView(btn);
            }
            box.addView(bar);
        }
        return box;
    }

    private int trackedScore(String pkg) {
        AppSum t = lastSums.get(pkg);
        return t == null ? 0 : t.blocked * 2 + t.suspicious;
    }

    /** The app's real icon (placeholder for unknown apps). */
    private Drawable icon(String pkg) {
        Drawable.ConstantState cs = iconCache.get(pkg);
        if (cs != null) return cs.newDrawable(getResources()).mutate();
        Drawable d;
        try {
            d = getPackageManager().getApplicationIcon(pkg);
        } catch (PackageManager.NameNotFoundException e) {
            d = getDrawable(R.drawable.ic_mark);
        }
        if (d.getConstantState() != null) iconCache.put(pkg, d.getConstantState());
        return d;
    }

    private String label(String pkg) {
        if (pkg.equals("?")) return "unknown app";
        if (pkg.startsWith("uid:")) return "system service (" + pkg + ")";
        String l = labelCache.get(pkg);
        if (l == null) {
            try {
                l = String.valueOf(getPackageManager().getApplicationLabel(getPackageManager().getApplicationInfo(pkg, 0)));
            } catch (PackageManager.NameNotFoundException e) {
                l = pkg;
            }
            labelCache.put(pkg, l);
        }
        return l;
    }

    private View withIcon(String pkg, View content, int sizeDp) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(android.view.Gravity.CENTER_VERTICAL);
        ImageView img = new ImageView(this);
        img.setImageDrawable(icon(pkg));
        img.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        row.addView(img, new LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMarginStart(dp(12));
        row.addView(content, lp);
        return row;
    }

    private View appBox(String pkg, View title, View sub, View extra) {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.addView(title);
        col.addView(sub);
        if (extra != null) col.addView(extra);
        LinearLayout box = new LinearLayout(this);
        box.setBackgroundResource(R.drawable.card);
        box.setPadding(28, 22, 28, 22);
        box.addView(withIcon(pkg, col, 40), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return box;
    }

    private void styleMode(TextView lock, TextView trust, String pkg) {
        int mode = Settings.appMode(this, pkg);
        lock.setText(mode == 1 ? "LOCKED IN BACKGROUND ✓" : "LOCK IN BACKGROUND");
        lock.setTextColor(getColor(mode == 1 ? R.color.acid : R.color.fg));
        lock.setBackgroundResource(mode == 1 ? R.drawable.pill_on : R.drawable.pill_off);
        trust.setText(mode == 2 ? "TRUSTED ✓" : "TRUST");
        trust.setTextColor(getColor(mode == 2 ? R.color.acid : R.color.fg));
        trust.setBackgroundResource(mode == 2 ? R.drawable.pill_on : R.drawable.pill_off);
    }

    /** Nullveil's own page for an app: what it can access, what Nullveil saw it do, and your controls. */
    private void showApp(String pkg) {
        boolean known = !pkg.equals("?") && !pkg.startsWith("uid:");
        int perms = known ? Watch.perms(this, pkg) : 0;
        String can = ((perms & Watch.MIC) != 0 ? "MIC " : "") + ((perms & Watch.CAM) != 0 ? "CAM " : "") + ((perms & Watch.LOC) != 0 ? "LOC" : "");
        int blocked = 0, suspicious = 0;
        StringBuilder recent = new StringBuilder();
        int lines = 0;
        for (Events.Entry e : Events.recent()) {
            if (!e.app.equals(pkg)) continue;
            if (e.blocked) blocked++;
            else if (e.score >= 3) suspicious++;
            if ((e.blocked || e.score >= 3) && lines++ < 6) {
                recent.append(e.blocked ? "✕ " : "◇ ").append(e.domain).append("\n   ").append(e.why).append("\n");
            }
        }
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(20), dp(20), dp(20), dp(8));
        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.VERTICAL);
        head.addView(plain(label(pkg), getColor(R.color.fg), 16));
        head.addView(plain(pkg, getColor(R.color.dim), 10));
        col.addView(withIcon(pkg, head, 48));
        TextView access = plain("\nCAN USE\n" + (can.trim().isEmpty() ? "no mic, camera or location permission" : can.trim()), getColor(R.color.fg), 12);
        col.addView(access);
        col.addView(plain("\nNULLVEIL SAW\n" + blocked + " blocked · " + suspicious + " suspicious (since the app opened)", getColor(R.color.fg), 12));
        if (recent.length() > 0) {
            TextView r = plain(recent.toString().trim(), getColor(R.color.alarm), 11);
            r.setPadding(0, dp(6), 0, 0);
            col.addView(r);
        }
        if (known) {
            TextView lock = plain("", getColor(R.color.fg), 11);
            TextView trust = plain("", getColor(R.color.fg), 11);
            for (TextView t : new TextView[]{lock, trust}) {
                t.setGravity(android.view.Gravity.CENTER);
                t.setPadding(dp(14), dp(12), dp(14), dp(12));
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                lp.topMargin = dp(12);
                t.setLayoutParams(lp);
            }
            styleMode(lock, trust, pkg);
            lock.setOnClickListener(v -> {
                Settings.toggleAppMode(this, pkg, 1);
                styleMode(lock, trust, pkg);
                Events.version.incrementAndGet();
            });
            trust.setOnClickListener(v -> {
                Settings.toggleAppMode(this, pkg, 2);
                styleMode(lock, trust, pkg);
                Events.version.incrementAndGet();
            });
            col.addView(lock);
            col.addView(trust);
            col.addView(plain("\nLOCK: no lookups while you are not using it.  TRUST: never blocked.", getColor(R.color.dim), 10));
        }
        ScrollView sv = new ScrollView(this);
        sv.addView(col);
        new AlertDialog.Builder(this).setView(sv).setPositiveButton("CLOSE", null).show();
    }

    private SpannableStringBuilder chip(int n, String label, int color) {
        SpannableStringBuilder sb = new SpannableStringBuilder(String.valueOf(n));
        int end = sb.length();
        sb.setSpan(new RelativeSizeSpan(2.4f), 0, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        sb.setSpan(new StyleSpan(Typeface.BOLD), 0, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        sb.setSpan(new ForegroundColorSpan(getColor(color)), 0, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        sb.append("\n").append(label);
        return sb;
    }

    private void open(Intent i) {
        try {
            startActivity(i);
        } catch (ActivityNotFoundException | SecurityException e) {
            Toast.makeText(this, "This screen is not available on your phone", Toast.LENGTH_SHORT).show();
        }
    }

    @SuppressWarnings("deprecation")
    private boolean mockLocationApp() {
        android.app.AppOpsManager a = getSystemService(android.app.AppOpsManager.class);
        return a.checkOpNoThrow("android:mock_location", android.os.Process.myUid(), getPackageName()) == android.app.AppOpsManager.MODE_ALLOWED;
    }

    /** Every permission and system switch Nullveil relies on, with a shortcut to fix each. */
    private void buildSteps() {
        steps.clear();
        String pkg = getPackageName();
        boolean vpn = VpnService.prepare(this) == null;
        steps.add(new Step("VPN permission", "lets Nullveil see DNS lookups. It never sees page contents.", vpn ? OK : BAD, true, () -> {
            Intent ask = VpnService.prepare(this);
            if (ask != null) consent.launch(ask);
        }));
        steps.add(new Step("Usage access", "lets Nullveil tell which app is in front, so background apps can be caught.",
                Watch.usageAccess(this) ? OK : BAD, true, () -> {
                    Intent i = new Intent(android.provider.Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.parse("package:" + pkg));
                    open(i);
                }));
        boolean notif = Build.VERSION.SDK_INT < 33 || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
        steps.add(new Step("Notifications", "needed to show the Ghost location notice.", notif ? OK : BAD, false, () -> {
            if (Build.VERSION.SDK_INT >= 33) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS);
        }));
        boolean battery = getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(pkg);
        steps.add(new Step("Keep running", "stops Android from putting Nullveil to sleep.", battery ? OK : BAD, true,
                () -> open(new Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + pkg)))));
        String pdns = android.provider.Settings.Global.getString(getContentResolver(), "private_dns_mode");
        steps.add(new Step("Private DNS must not be strict",
                "a named Private DNS provider skips Nullveil. Set it to Off or Automatic.", "hostname".equals(pdns) ? BAD : OK, true,
                () -> open(new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS))));
        steps.add(new Step("Always-on VPN", "turn on Always-on for Nullveil so it starts after a reboot.", INFO, false,
                () -> open(new Intent(android.provider.Settings.ACTION_VPN_SETTINGS))));
        boolean ghostReady = mockLocationApp();
        steps.add(new Step("Ghost mode access", ghostReady ? "ready: Ghost mode can show apps a different position."
                : "locked: Android allows this only after a one-time unlock. Tap for how.", ghostReady ? OK : BAD, false, this::ghostHelp));
        boolean micOk = checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED;
        steps.add(new Step("Microphone (for Mic Guard)",
                "Nullveil holds the mic so every other app hears silence. It reads audio only to keep hold, then drops it: never stored, never sent.",
                micOk ? OK : INFO, false, () -> micPerm.launch(Manifest.permission.RECORD_AUDIO)));
        String keyLevel = SecureStore.level();
        steps.add(new Step("Stored data encryption", "AES-256-GCM, key held in: " + keyLevel + ". Your overrides are unreadable without this phone.",
                keyLevel.equals("software only") || keyLevel.equals("unavailable") ? INFO : OK, false, () -> { }));
    }

    private View stepRow(Step st) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackgroundResource(R.drawable.card);
        box.setPadding(28, 22, 28, 22);
        int color = getColor(st.state == OK ? R.color.acid : st.state == BAD ? R.color.alarm : R.color.dim);
        TextView title = line((st.state == OK ? "●  " : st.state == BAD ? "○  " : "◇  ") + st.title, color);
        title.setBackground(null);
        title.setPadding(0, 0, 0, 0);
        title.setTextSize(13);
        TextView detail = line(st.detail, getColor(R.color.dim));
        detail.setBackground(null);
        detail.setPadding(0, 6, 0, 0);
        box.addView(title);
        box.addView(detail);
        return box;
    }
}
