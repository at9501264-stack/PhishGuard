import { lazy } from 'react'
import { Route, Routes } from 'react-router-dom'
import { Layout } from './layout/Layout'

// Every page is its own chunk; Layout wraps <Outlet /> in a Suspense skeleton while one loads.
const Overview = lazy(() => import('./pages/Overview'))
const ScanPage = lazy(() => import('./pages/Scan'))
const Report = lazy(() => import('./pages/Report'))
const DomainPage = lazy(() => import('./pages/Domain'))
const History = lazy(() => import('./pages/History'))
const Bulk = lazy(() => import('./pages/Bulk'))
const Analytics = lazy(() => import('./pages/Analytics'))
const Graph = lazy(() => import('./pages/Graph'))
const ModelLab = lazy(() => import('./pages/ModelLab'))
const Watchlist = lazy(() => import('./pages/Watchlist'))
const Typosquat = lazy(() => import('./pages/Typosquat'))
const Community = lazy(() => import('./pages/Community'))
const Feeds = lazy(() => import('./pages/Feeds'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Activity = lazy(() => import('./pages/Activity'))
const SettingsPage = lazy(() => import('./pages/Settings'))
const ApiGuide = lazy(() => import('./pages/ApiGuide'))
const NotFound = lazy(() => import('./pages/NotFound'))

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="scan" element={<ScanPage />} />
        <Route path="scans/:id" element={<Report />} />
        <Route path="domains/:domain" element={<DomainPage />} />
        <Route path="history" element={<History />} />
        <Route path="bulk" element={<Bulk />} />
        <Route path="bulk/:id" element={<Bulk />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="graph" element={<Graph />} />
        <Route path="model" element={<ModelLab />} />
        <Route path="watchlist" element={<Watchlist />} />
        <Route path="typosquat" element={<Typosquat />} />
        <Route path="community" element={<Community />} />
        <Route path="feeds" element={<Feeds />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="activity" element={<Activity />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="api-guide" element={<ApiGuide />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  )
}
