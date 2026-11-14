// visit.js — counts this page's visit, and reports what the page counts as it goes (core.js says so with sg:count
// events). Its own module, so that importing count.js never counts anything, and core.js needs no import.
import { count, countVisit } from './count.js';

document.addEventListener('sg:count', (e) => count(e.detail.event, e.detail.details));
countVisit();
