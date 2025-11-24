package br.edu.icev.aed;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.Optional;

/*
 * SolucaoForense
 *
 * Implementa os 5 desafios descritos no enunciado.
 *
 * Observação importante:
 * - Presumo a existência da interface br.edu.icev.aed.forense.AnaliseForenseAvancada
 *   e da classe br.edu.icev.aed.forense.Alerta no analise-forense-api.jar fornecido.
 * - Caso a assinatura exata dos métodos na interface seja diferente, adapte os nomes/assinaturas
 *   mas mantenha a lógica apresentada abaixo.
 */
public class SolucaoForense implements br.edu.icev.aed.forense.AnaliseForenseAvancada {

    // Um helper para parse CSV simples (linha já sem cabeçalho)
    private static class LogEntry {
        long timestamp;
        String userId;
        String sessionId;
        String actionType;
        String targetResource;
        int severity;
        long bytesTransferred;

        static LogEntry fromCsvLine(String line) {
            // Split simples por vírgula - assume que campos não contém vírgulas internas.
            String[] cols = line.split(",", -1);
            LogEntry e = new LogEntry();
            e.timestamp = Long.parseLong(cols[0].trim());
            e.userId = cols[1].trim();
            e.sessionId = cols[2].trim();
            e.actionType = cols[3].trim();
            e.targetResource = cols[4].trim();
            e.severity = Integer.parseInt(cols[5].trim());
            e.bytesTransferred = Long.parseLong(cols[6].trim());
            return e;
        }
    }

    private static List<LogEntry> readAll(Reader reader) throws IOException {
        BufferedReader br = new BufferedReader(reader);
        List<LogEntry> list = new ArrayList<>();
        String header = br.readLine(); // pular cabeçalho
        String line;
        while ((line = br.readLine()) != null) {
            if (line.trim().isEmpty()) continue;
            list.add(LogEntry.fromCsvLine(line));
        }
        return list;
    }

    // ========== Desafio 1 ==========
    // Encontra sessões inválidas segundo a lógica do enunciado.
    @Override
    public Set<String> encontrarSessoesInvalidas(java.io.InputStream csvStream) throws IOException {
        List<LogEntry> logs = readAll(new java.io.InputStreamReader(csvStream));
        // Map USER_ID -> Stack<SESSION_ID>
        Map<String, Deque<String>> stacks = new HashMap<>();
        Set<String> invalids = new LinkedHashSet<>();

        for (LogEntry e : logs) {
            Deque<String> st = stacks.computeIfAbsent(e.userId, k -> new ArrayDeque<>());
            if ("LOGIN".equalsIgnoreCase(e.actionType)) {
                if (!st.isEmpty()) {
                    // login aninhado => sessão atual (topo) passa a ser inválida
                    invalids.add(st.peek());
                }
                st.push(e.sessionId);
            } else if ("LOGOUT".equalsIgnoreCase(e.actionType)) {
                if (st.isEmpty() || !Objects.equals(st.peek(), e.sessionId)) {
                    // logout sem topo correspondente -> sessão inválida
                    invalids.add(e.sessionId);
                } else {
                    st.pop();
                }
            }
        }

        // Após processar tudo, quaisquer sessionIds remanescentes nas pilhas são inválidas
        for (Deque<String> st : stacks.values()) {
            for (String sid : st) invalids.add(sid);
        }

        return invalids;
    }

    // ========== Desafio 2 ==========
    // Reconstrói linha do tempo de uma sessionId (apenas ACTION_TYPEs, em ordem)
    @Override
    public List<String> reconstruirLinhaDoTempo(java.io.InputStream csvStream, String sessionId) throws IOException {
        List<LogEntry> logs = readAll(new java.io.InputStreamReader(csvStream));
        List<String> result = new ArrayList<>();
        for (LogEntry e : logs) {
            if (e.sessionId.equals(sessionId)) {
                result.add(e.actionType);
            }
        }
        return result;
    }

    // ========== Desafio 3 ==========
    // Prioriza alertas por SEVERITY_LEVEL, retorna os n mais severos.
    @Override
    public List<br.edu.icev.aed.forense.Alerta> priorizarAlertas(java.io.InputStream csvStream, int n) throws IOException {
        List<LogEntry> logs = readAll(new java.io.InputStreamReader(csvStream));
        if (n <= 0) return Collections.emptyList();

        // Comparator que ordena por severity desc (maior prioridade primeiro).
        Comparator<br.edu.icev.aed.forense.Alerta> cmp = Comparator.comparingInt(br.edu.icev.aed.forense.Alerta::getSeverityLevel).reversed();

        PriorityQueue<br.edu.icev.aed.forense.Alerta> pq = new PriorityQueue<>(cmp);

        for (LogEntry e : logs) {
            // Supondo que Alerta tem um construtor compatível; se não tiver, adapte.
            br.edu.icev.aed.forense.Alerta a = new br.edu.icev.aed.forense.Alerta(
                    e.timestamp,
                    e.userId,
                    e.sessionId,
                    e.actionType,
                    e.targetResource,
                    e.severity,
                    e.bytesTransferred
            );
            pq.add(a);
        }

        List<br.edu.icev.aed.forense.Alerta> out = new ArrayList<>();
        for (int i = 0; i < n && !pq.isEmpty(); i++) {
            out.add(pq.poll());
        }
        return out;
    }

    // ========== Desafio 4 ==========
    // Next Greater Element para BYTES_TRANSFERRED:
    // retorna Map<timestamp_A, timestamp_B> onde B é o primeiro depois de A com bytes > bytes_A
    @Override
    public Map<Long, Long> encontrarPicosTransferencia(java.io.InputStream csvStream) throws IOException {
        List<LogEntry> logs = readAll(new java.io.InputStreamReader(csvStream));
        int m = logs.size();
        Map<Long, Long> result = new LinkedHashMap<>();

        // Trabalhar apenas com eventos cujo BYTES_TRANSFERRED > 0? Spec diz: se não houver >0, retorna vazio.
        boolean anyPositive = logs.stream().anyMatch(le -> le.bytesTransferred > 0);
        if (!anyPositive) return result;

        // Implementação do Next Greater Element usando stack, iterando da direita para a esquerda.
        Deque<LogEntry> stack = new ArrayDeque<>();
        for (int i = m - 1; i >= 0; i--) {
            LogEntry cur = logs.get(i);
            long curBytes = cur.bytesTransferred;
            while (!stack.isEmpty() && stack.peek().bytesTransferred <= curBytes) {
                stack.pop();
            }
            if (!stack.isEmpty()) {
                result.put(cur.timestamp, stack.peek().timestamp);
            }
            stack.push(cur);
        }

        return result;
    }

    // ========== Desafio 5 ==========
    // BFS entre recursos (TARGET_RESOURCE). Agrupa por sessão e cria arestas A->B quando em mesma sessão
    @Override
    public Optional<List<String>> rastrearContaminacao(java.io.InputStream csvStream, String recursoInicial, String recursoAlvo) throws IOException {
        List<LogEntry> logs = readAll(new java.io.InputStreamReader(csvStream));
        // Montar grafo: Map<resource, List<resource>>
        Map<String, List<String>> g = new HashMap<>();

        // Agrupar logs por sessionId (ordem já cronológica)
        Map<String, List<LogEntry>> bySession = logs.stream().collect(Collectors.groupingBy(le -> le.sessionId, LinkedHashMap::new, Collectors.toList()));

        for (List<LogEntry> sessLogs : bySession.values()) {
            for (int i = 0; i + 1 < sessLogs.size(); i++) {
                String a = sessLogs.get(i).targetResource;
                String b = sessLogs.get(i + 1).targetResource;
                if (a == null || b == null) continue;
                g.computeIfAbsent(a, k -> new ArrayList<>());
                g.computeIfAbsent(b, k -> new ArrayList<>());
                g.get(a).add(b);
            }
        }

        // Se recursoInicial == recursoAlvo e existe no grafo, retorna lista com 1 elemento
        if (Objects.equals(recursoInicial, recursoAlvo) && g.containsKey(recursoInicial)) {
            return Optional.of(Collections.singletonList(recursoInicial));
        }

        // BFS
        Queue<String> q = new ArrayDeque<>();
        Map<String, String> pred = new HashMap<>();
        Set<String> visited = new HashSet<>();

        q.add(recursoInicial);
        visited.add(recursoInicial);

        boolean found = false;
        while (!q.isEmpty() && !found) {
            String u = q.poll();
            List<String> neighbors = g.getOrDefault(u, Collections.emptyList());
            for (String v : neighbors) {
                if (!visited.contains(v)) {
                    visited.add(v);
                    pred.put(v, u);
                    if (v.equals(recursoAlvo)) {
                        found = true;
                        break;
                    }
                    q.add(v);
                }
            }
        }

        if (!found) return Optional.empty();

        // Reconstruir caminho
        LinkedList<String> path = new LinkedList<>();
        String cur = recursoAlvo;
        while (cur != null) {
            path.addFirst(cur);
            cur = pred.get(cur);
        }
        // Garantir que o primeiro seja recursoInicial
        if (!path.isEmpty() && path.getFirst().equals(recursoInicial)) {
            return Optional.of(path);
        } else {
            return Optional.empty();
        }
    }
}
