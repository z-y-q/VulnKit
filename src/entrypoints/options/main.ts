import { mount, unmount } from 'svelte';
import '../../styles/shared.css';
import App from './App.svelte';

const app = mount(App, {
  target: document.getElementById('app')!,
});

export default app;
