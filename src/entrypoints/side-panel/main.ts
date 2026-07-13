import App from './App.svelte';
import { mount, unmount } from 'svelte';
import 'virtual:uno.css';
import '../../styles/shared.css';
import './app.css';

const app = mount(App, {
  target: document.getElementById('app')!,
});

if (import.meta.hot) {
  import.meta.hot.accept();
  import.meta.hot.dispose(() => {
    unmount(app);
  });
}
