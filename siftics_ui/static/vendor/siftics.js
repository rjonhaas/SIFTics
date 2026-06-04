/* siftics.js — vanilla JS replacing HTMX */
(function () {
  'use strict';

  // ------------------------------------------------------------------
  // fetch helpers
  // ------------------------------------------------------------------

  function fetchHTML(url, target) {
    fetch(url)
      .then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
      .then(function (html) {
        var el = typeof target === 'string' ? document.querySelector(target) : target;
        if (el) el.innerHTML = html;
      })
      .catch(function () {});
  }

  // POST a form element; on success either follow an X-Redirect header
  // or update targetSel with the response HTML.
  function postForm(form, targetSel, opts) {
    opts = opts || {};
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      _doPost(form.action, new FormData(form), targetSel, form, opts);
    });
  }

  // POST raw FormData from a button (not a form submit).
  function postButton(btn, url, formDataFn, targetSel, opts) {
    opts = opts || {};
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      _doPost(url, formDataFn(), targetSel, btn, opts);
    });
  }

  function _doPost(url, body, targetSel, trigger, opts) {
    if (trigger) trigger.disabled = true;
    fetch(url, { method: 'POST', body: body })
      .then(function (r) {
        var redirect = r.headers.get('X-Redirect') || r.headers.get('HX-Redirect');
        if (redirect) { window.location.href = redirect; return null; }
        return r.text().then(function (html) {
          return { html: html, ok: r.ok };
        });
      })
      .then(function (result) {
        if (!result) return;
        var el = targetSel
          ? (typeof targetSel === 'string' ? document.querySelector(targetSel) : targetSel)
          : null;
        if (el) el.innerHTML = result.html;
        if (opts.onDone) opts.onDone(result);
      })
      .catch(function () {
        var el = targetSel
          ? (typeof targetSel === 'string' ? document.querySelector(targetSel) : targetSel)
          : null;
        if (el) el.innerHTML = '<p class="text-rose-400">&#x26A0; Request failed — check connection.</p>';
      })
      .finally(function () {
        if (trigger) trigger.disabled = false;
      });
  }

  // ------------------------------------------------------------------
  // SSE
  // ------------------------------------------------------------------

  var _sseSource = null;
  var _sseHandlers = {};   // eventName -> [fn, ...]

  function onSSE(eventName, fn) {
    if (!_sseHandlers[eventName]) _sseHandlers[eventName] = [];
    _sseHandlers[eventName].push(fn);
    if (_sseSource) _bindSSE(_sseSource, eventName);
  }

  function _bindSSE(src, eventName) {
    src.addEventListener(eventName, function (e) {
      (_sseHandlers[eventName] || []).forEach(function (fn) { fn(e); });
    });
  }

  function connectSSE(url) {
    function _connect() {
      var src = new EventSource(url);
      _sseSource = src;
      Object.keys(_sseHandlers).forEach(function (ev) { _bindSSE(src, ev); });
      src.onerror = function () {
        src.close();
        _sseSource = null;
        setTimeout(_connect, 3000);
      };
    }
    _connect();
  }

  // Refresh an element from a URL whenever any of the listed SSE events fire,
  // and also on an interval (ms). Pass interval=0 to skip polling.
  function livePanel(targetSel, url, sseEvents, interval) {
    function refresh() { fetchHTML(url, targetSel); }
    (sseEvents || []).forEach(function (ev) { onSSE(ev, refresh); });
    if (interval > 0) setInterval(refresh, interval);
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  window.Siftics = {
    fetchHTML: fetchHTML,
    postForm:  postForm,
    postButton: postButton,
    onSSE:     onSSE,
    connectSSE: connectSSE,
    livePanel: livePanel,
  };

})();
