# Hotel booking management dashboard

## Preview

![localhost_5173_dashboard (1)](https://github.com/user-attachments/assets/f3a0a2bb-bb36-4576-b72d-07fef18aa331)


[Application URL, click and explore!](https://hotelbooking-oqevfug02-wontae-chois-projects-63012546.vercel.app)

### Notice

**Login credentials**

Id: test@test.com
Password: test1234

## Tech Stack

- React.js
- Supabase database, storage, email authentication and row level security
- React query
- React-router-dom(dynamic routing with search URL and path, nested routing)
- Context API (darkmode implementation & compound components)
- Rechart
- React-hook-form
- Styled components

## Contributions

**Overview**

A dashboard app for hotel staff to manage bookings.  

The dashboard includes charts providing an overview of booking status, and an interface to quickly process check-ins/check-outs for the current day.

## Main Features

1. Supabase email OAuth and image storage.
2. Visualization and charts showing check-in status, revenue, and booking rates based on room availability.
3. Ability to process check-ins/check-outs for today's bookings from the dashboard.
4. Detailed booking page displaying guest information, check-in/check-out dates, room details, breakfast inclusion, etc.
5. Cabin dashboard where cabins can be sorted by price or capacity, with options to edit, add, or delete room information.
6. Ability to create hotel staff accounts.
7. Modifying global hotel system settings, such as minimum/maximum nights, maximum guests, and breakfast prices.

## Build

```bash
npm install && npm update
npm run build
```