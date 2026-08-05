import { mount } from 'svelte';
import '../../styles/shared.css';
import 'virtual:uno.css';
import App from './App.svelte';

mount(App, { target: document.getElementById('app')! });
